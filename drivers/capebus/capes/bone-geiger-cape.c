/*
 * Driver for beaglebone Geiger cape
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>
#include <linux/pinctrl/consumer.h>
#include <linux/atomic.h>
#include <linux/clk.h>
#include <linux/interrupt.h>
#include <asm/barrier.h>
#include <plat/clock.h>
#include <plat/omap_device.h>
#include <linux/clkdev.h>
#include <linux/pwm.h>
#include <linux/math64.h>
#include <linux/atomic.h>
#include <linux/leds.h>
#include <linux/input/ti_tsc.h>
#include <linux/platform_data/ti_adc.h>
#include <linux/mfd/ti_tscadc.h>
#include <plat/omap_device.h>
#include <linux/iio/iio.h>
#include <linux/iio/machine.h>
#include <linux/iio/consumer.h>

#include <linux/capebus/capebus-bone.h>

/* fwd decl. */
extern struct cape_driver bonegeiger_driver;

struct bone_geiger_info {
	struct cape_dev *dev;
	struct platform_device *leds_pdev;
	struct pwm_device *pwm_dev;
	int pwm_frequency;
	int pwm_duty_cycle;
	int run;
	atomic64_t counter;
	int event_gpio;
	int event_irq;
	struct led_trigger *event_led;		/* event detect */
	struct led_trigger *run_led;		/* running      */
	unsigned long event_blink_delay;
	struct sysfs_dirent *counter_sd;	/* notifier */
	struct platform_device *tscadc_pdev;
	const char *vsense_name;
	unsigned int vsense_scale;
	struct iio_channel *vsense_channel;
};

static const struct of_device_id bonegeiger_of_match[] = {
	{
		.compatible = "bone-geiger-cape",
	},
	{ },
};
MODULE_DEVICE_TABLE(of, bonegeiger_of_match);

static int bonegeiger_start(struct cape_dev *dev)
{
	struct bone_geiger_info *info = dev->drv_priv;
	int duty, period;

	if (info->run != 0)
		return 0;

	/* checks */
	if (info->pwm_frequency < 1000 || info->pwm_frequency > 50000) {
		dev_err(&dev->dev, "Cowardly refusing to use a "
				"frequency of %d\n",
				info->pwm_frequency);
		return -EINVAL;
	}
	if (info->pwm_duty_cycle > 80) {
		dev_err(&dev->dev, "Cowardly refusing to use a "
				"duty cycle of %d\n",
				info->pwm_duty_cycle);
		return -EINVAL;
	}

	period = div_u64(1000000000LLU, info->pwm_frequency);
	duty = (period * info->pwm_duty_cycle) / 100;

	dev_info(&dev->dev, "starting geiger tube with "
			"duty=%duns period=%dus\n",
			duty, period);

	pwm_config(info->pwm_dev, duty, period);
	pwm_enable(info->pwm_dev);

	info->run = 1;
	led_trigger_event(info->run_led, LED_FULL);

	return 0;
}

static int bonegeiger_stop(struct cape_dev *dev)
{
	struct bone_geiger_info *info = dev->drv_priv;

	if (info->run == 0)
		return 0;

	dev_info(&dev->dev, "disabling geiger tube\n");
	pwm_config(info->pwm_dev, 0, 50000);	/* 0% duty cycle, 20KHz */
	pwm_disable(info->pwm_dev);

	info->run = 0;
	led_trigger_event(info->run_led, LED_OFF);

	return 0;
}

static ssize_t bonegeiger_show_run(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct cape_dev *cdev = to_cape_dev(dev);
	struct bone_geiger_info *info = cdev->drv_priv;

	return sprintf(buf, "%d\n", info->run);
}

static ssize_t bonegeiger_store_run(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct cape_dev *cdev = to_cape_dev(dev);
	int run, err;

	if (sscanf(buf, "%i", &run) != 1)
		return -EINVAL;

	if (run)
		err = bonegeiger_start(cdev);
	else
		err = bonegeiger_stop(cdev);

	return err ? err : count;
}

static ssize_t bonegeiger_show_counter(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct cape_dev *cdev = to_cape_dev(dev);
	struct bone_geiger_info *info = cdev->drv_priv;

	return sprintf(buf, "%llu\n", atomic64_read(&info->counter));
}

static ssize_t bonegeiger_store_counter(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct cape_dev *cdev = to_cape_dev(dev);
	struct bone_geiger_info *info = cdev->drv_priv;

	atomic64_set(&info->counter, 0);	/* just reset */
	return count;
}

static ssize_t bonegeiger_show_vsense(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct cape_dev *cdev = to_cape_dev(dev);
	struct bone_geiger_info *info = cdev->drv_priv;
	int ret, val;
	u32 mvolts;

	ret = iio_read_channel_raw(info->vsense_channel, &val);
	if (ret < 0)
		return ret;

	/* V = (1800 / 4096) * val * scale) = (1.8 * val * scale / 4096) */
	mvolts = div_u64(1800 * info->vsense_scale * (u64)val, 4096 * 100);

	return sprintf(buf, "%d\n", mvolts);
}

static DEVICE_ATTR(run, S_IRUGO | S_IWUSR,
		bonegeiger_show_run, bonegeiger_store_run);
static DEVICE_ATTR(counter, S_IRUGO | S_IWUSR,
		bonegeiger_show_counter, bonegeiger_store_counter);
static DEVICE_ATTR(vsense, S_IRUGO,
		bonegeiger_show_vsense, NULL);

static int bonegeiger_sysfs_register(struct cape_dev *cdev)
{
	int err;

	err = device_create_file(&cdev->dev, &dev_attr_run);
	if (err != 0)
		goto err_no_run;

	err = device_create_file(&cdev->dev, &dev_attr_counter);
	if (err != 0)
		goto err_no_counter;

	err = device_create_file(&cdev->dev, &dev_attr_vsense);
	if (err != 0)
		goto err_no_vsense;

	return 0;

err_no_vsense:
	device_remove_file(&cdev->dev, &dev_attr_counter);
err_no_counter:
	device_remove_file(&cdev->dev, &dev_attr_run);
err_no_run:
	return err;
}

static void bonegeiger_sysfs_unregister(struct cape_dev *cdev)
{
	device_remove_file(&cdev->dev, &dev_attr_vsense);
	device_remove_file(&cdev->dev, &dev_attr_counter);
	device_remove_file(&cdev->dev, &dev_attr_run);
}

static irqreturn_t bonegeiger_irq_handler(int irq, void *dev_id)
{
	struct cape_dev *dev = dev_id;
	struct bone_geiger_info *info = dev->drv_priv;

	atomic64_inc(&info->counter);

	led_trigger_blink_oneshot(info->event_led,
		  &info->event_blink_delay, &info->event_blink_delay, 0);

	sysfs_notify_dirent(info->counter_sd);

	return IRQ_HANDLED;
}

static int bonegeiger_probe(struct cape_dev *dev, const struct cape_device_id *id)
{
	static const struct of_device_id gpio_leds_of_match[] = {
		{ .compatible = "gpio-leds", }, { },
	};
	static const struct of_device_id ti_tscadc_dt_of_match[] = {
		{ .compatible = "ti-tscadc-dt", }, { },
	};
	char boardbuf[33];
	char versionbuf[5];
	const char *board_name;
	const char *version;
	const struct of_device_id *match;
	struct bone_geiger_info *info;
	struct pinctrl *pinctrl;
	u32 val;
	int err;

	/* get the board name (after check of cntrlboard match) */
	board_name = bone_capebus_id_get_field(id, BONE_CAPEBUS_BOARD_NAME,
			boardbuf, sizeof(boardbuf));
	if (board_name == NULL)
		return -ENODEV;

	/* match compatible? */
	match = capebus_of_match_device(dev, "board-name", board_name);
	if (match == NULL)
		return -ENODEV;

	/* get the board version */
	version = bone_capebus_id_get_field(id, BONE_CAPEBUS_VERSION,
			versionbuf, sizeof(versionbuf));
	if (version == NULL)
		return -ENODEV;

	dev_info(&dev->dev, "%s: V=%s initialized - '%s'\n", board_name,
			version, match->compatible);

	dev->drv_priv = devm_kzalloc(&dev->dev, sizeof(*info), GFP_KERNEL);
	if (dev->drv_priv == NULL) {
		dev_err(&dev->dev, "Failed to allocate info\n");
		err = -ENOMEM;
		goto err_no_mem;
	}
	info = dev->drv_priv;

	dev_info(&dev->dev, "LED pdev created OK\n");

	dev_info(&dev->dev, "Configuring PWM pins\n");

	pinctrl = devm_pinctrl_get_select_default(&dev->dev);
	if (IS_ERR(pinctrl))
		dev_warn(&dev->dev,
			"pins are not configured from the driver\n");

	dev_info(&dev->dev, "Getting PWM device\n");

	/* NOTE: No versioning! */
	info->pwm_dev = pwm_get(&dev->dev, NULL);
	if (IS_ERR(info->pwm_dev)) {
		dev_err(&dev->dev, "unable to request PWM\n");
		err = PTR_ERR(info->pwm_dev);
		goto err_no_pwm;
	}

	dev_info(&dev->dev, "Got PWM OK\n");

	if (of_property_read_u32(dev->dev.of_node, "pwm-frequency",
				&val) != 0) {
		val = 20000;
		dev_warn(&dev->dev, "Could not read pwm-frequency property; "
				"using default %u\n",
				val);
	}
	info->pwm_frequency = val;

	if (of_property_read_u32(dev->dev.of_node, "pwm-duty-cycle",
				&val) != 0) {
		val = 60;
		dev_warn(&dev->dev, "Could not read pwm-duty-cycle property; "
				"using default %u\n",
				val);
	}
	info->pwm_duty_cycle = val;

	dev_info(&dev->dev, "PWM configuration: Freq = %dHz, "
			"duty cycle = %d%%\n",
			info->pwm_frequency, info->pwm_duty_cycle);

	info->event_gpio = of_get_gpio_flags(dev->dev.of_node, 0, NULL);
	if (IS_ERR_VALUE(info->event_gpio)) {
		dev_err(&dev->dev, "unable to get event GPIO\n");
		err = info->event_gpio;
		goto err_no_gpio;
	}

	dev_info(&dev->dev, "Got event GPIO %d\n", info->event_gpio);

	err = gpio_request_one(info->event_gpio,
			GPIOF_DIR_IN | GPIOF_EXPORT,
			"bone-geiger-cape-event");
	if (err != 0) {
		dev_err(&dev->dev, "failed to request event GPIO\n");
		goto err_no_gpio;
	}

	dev_info(&dev->dev, "Requested GPIO %d\n", info->event_gpio);

	atomic64_set(&info->counter, 0);

	info->event_irq = gpio_to_irq(info->event_gpio);
	if (IS_ERR_VALUE(info->event_irq)) {
		dev_err(&dev->dev, "unable to get event GPIO IRQ\n");
		err = info->event_irq;
		goto err_no_irq;
	}

	err = request_irq(info->event_irq, bonegeiger_irq_handler,
			IRQF_TRIGGER_RISING | IRQF_SHARED,
			"bone-geiger-irq", dev);
	if (err != 0) {
		dev_err(&dev->dev, "unable to request irq\n");
		goto err_no_irq;
	}

	err = bonegeiger_sysfs_register(dev);
	if (err != 0) {
		dev_err(&dev->dev, "unable to register sysfs\n");
		goto err_no_sysfs;
	}

	info->counter_sd = sysfs_get_dirent(dev->dev.kobj.sd, NULL, "counter");
	if (info->counter_sd == NULL) {
		dev_err(&dev->dev, "unable to get dirent of counter\n");
		err = -ENODEV;
		goto err_no_counter_dirent;
	}

	led_trigger_register_simple("geiger-event", &info->event_led);
	led_trigger_register_simple("geiger-run", &info->run_led);

	/* must be last, for the led-trigger to be picked up */
	info->leds_pdev = capebus_of_platform_compatible_device_create(dev,
			gpio_leds_of_match, "geiger-cape-leds",
			"version", version);
	if (IS_ERR(info->leds_pdev)) {
		info->leds_pdev = NULL;
		dev_err(&dev->dev, "Failed to create platform led "
				"platform device\n");
		err = -ENODEV;
		goto err_no_leds_pdev;
	}

	led_trigger_event(info->run_led, LED_OFF);

	/* default */
	if (of_property_read_u32(dev->dev.of_node, "event-blink-delay",
				&val) != 0) {
		val = 30;
		dev_warn(&dev->dev, "Could not read event-blink-delay "
				"property; using default %u\n",
					val);
	}
	info->event_blink_delay = val;

	info->tscadc_pdev = capebus_of_platform_compatible_device_create(dev,
			ti_tscadc_dt_of_match, "geiger-cape-ti-tscadc",
			"version", version);
	if (info->tscadc_pdev == NULL) {
		dev_err(&dev->dev, "Could not create tsc_adc device\n");
		err = -ENODEV;
		goto err_no_tsc_pdev;
	}

	/* default */
	if (of_property_read_string(dev->dev.of_node, "vsense-name",
				&info->vsense_name) != 0) {
		info->vsense_name = "AIN5";
		dev_warn(&dev->dev, "Could not read vsense-name property; "
				"using default %u\n",
					val);
	}

	if (of_property_read_u32(dev->dev.of_node, "vsense-scale",
				&info->vsense_scale) != 0) {
		info->vsense_scale = 37325;	/* 373.25 */
		dev_warn(&dev->dev, "Could not read vsense-scale property; "
				"using default %u\n",
					info->vsense_scale);
	}

	info->vsense_channel = iio_channel_get(NULL, info->vsense_name);
	if (IS_ERR(info->vsense_channel)) {
		dev_err(&dev->dev, "Could not get AIN5 analog input\n");
		err = PTR_ERR(info->vsense_channel);
		goto err_no_vsense;
	}

	dev_info(&dev->dev, "Initialization complete\n");

	return 0;
err_no_vsense:
	of_device_unregister(info->tscadc_pdev);
err_no_tsc_pdev:
	of_device_unregister(info->leds_pdev);
err_no_leds_pdev:
	led_trigger_unregister_simple(info->run_led);
	led_trigger_unregister_simple(info->event_led);
	sysfs_put(info->counter_sd);
err_no_counter_dirent:
	bonegeiger_sysfs_unregister(dev);
err_no_sysfs:
	free_irq(info->event_irq, dev);
err_no_irq:
	gpio_free(info->event_gpio);
err_no_gpio:
	pwm_put(info->pwm_dev);
err_no_pwm:
	devm_kfree(&dev->dev, info);
err_no_mem:
	return err;
}

static void bonegeiger_remove(struct cape_dev *dev)
{
	struct bone_geiger_info *info = dev->drv_priv;

	dev_info(&dev->dev, "Removing geiger cape driver...\n");

	bonegeiger_stop(dev);

	iio_channel_release(info->vsense_channel);

	of_device_unregister(info->tscadc_pdev);
	of_device_unregister(info->leds_pdev);

	led_trigger_unregister_simple(info->run_led);
	led_trigger_unregister_simple(info->event_led);
	sysfs_put(info->counter_sd);
	bonegeiger_sysfs_unregister(dev);
	free_irq(info->event_irq, dev);
	gpio_free(info->event_gpio);
	pwm_put(info->pwm_dev);
}

struct cape_driver bonegeiger_driver = {
	.driver = {
		.name		= "bonegeiger",
		.owner		= THIS_MODULE,
		.of_match_table	= bonegeiger_of_match,
	},
	.probe		= bonegeiger_probe,
	.remove		= bonegeiger_remove,
};

module_capebus_driver(bonegeiger_driver);

MODULE_AUTHOR("Pantelis Antoniou");
MODULE_DESCRIPTION("Beaglebone geiger cape");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:bone-geiger-cape");
