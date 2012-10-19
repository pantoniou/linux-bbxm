/*
 * Driver for beaglebone LCD[347] cape
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
#include <asm/barrier.h>
#include <plat/clock.h>
#include <plat/omap_device.h>
#include <linux/clkdev.h>
#include <linux/input/ti_tsc.h>
#include <linux/platform_data/ti_adc.h>
#include <linux/mfd/ti_tscadc.h>

#include <linux/capebus/capebus-bone.h>

/* fwd decl. */
extern struct cape_driver bonelcd_driver;

struct bone_lcd_info {
	struct cape_dev *dev;
	struct platform_device *leds_pdev;
	struct platform_device *da8xx_dt_pdev;
	struct platform_device *bl_pdev;
	struct platform_device *keys_pdev;
	struct platform_device *tscadc_pdev;
};

#define BONE_LCD_TYPE(x)	((void *)(unsigned long)(x))

static const struct of_device_id bonelcd_of_match[] = {
	{
		.compatible = "bone-lcd3-cape",
		.data	    = BONE_LCD_TYPE(3),
	}, {
		.compatible = "bone-lcd4-cape",
		.data	    = BONE_LCD_TYPE(4),
	}, {
		.compatible = "bone-lcd7-cape",
		.data	    = BONE_LCD_TYPE(7),
	},
	{ },
};
MODULE_DEVICE_TABLE(of, bonelcd_of_match);

static int bonelcd_probe(struct cape_dev *dev, const struct cape_device_id *id)
{
	static const struct of_device_id gpio_leds_of_match[] = {
		{ .compatible = "gpio-leds", }, { },
	};
	static const struct of_device_id tps_bl_of_match[] = {
		{ .compatible = "tps65217-backlight", }, { },
	};
	static const struct of_device_id gpio_keys_of_match[] = {
		{ .compatible = "gpio-keys", }, { },
	};
	static const struct of_device_id ti_tscadc_dt_of_match[] = {
		{ .compatible = "ti-tscadc-dt", }, { },
	};
	static const struct of_device_id da8xx_dt_of_match[] = {
		{ .compatible = "da8xx-dt", }, { },
	};
	char boardbuf[33];
	char versionbuf[5];
	const char *board_name;
	const char *version;
	const struct of_device_id *match;
	struct bone_lcd_info *info;
	struct pinctrl *pinctrl;
	int err;

	/* get the board name (also matches the cntrlboard before checking) */
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

	pinctrl = devm_pinctrl_get_select_default(&dev->dev);
	if (IS_ERR(pinctrl))
		dev_warn(&dev->dev,
			"pins are not configured from the driver\n");

	dev_info(&dev->dev, "%s: V=%s '%s'\n", board_name,
			version, match->compatible);

	dev->drv_priv = devm_kzalloc(&dev->dev, sizeof(*info), GFP_KERNEL);
	if (dev->drv_priv == NULL) {
		dev_err(&dev->dev, "Failed to allocate info\n");
		err = -ENOMEM;
		goto err_no_mem;
	}
	info = dev->drv_priv;

	info->leds_pdev = capebus_of_platform_compatible_device_create(dev,
			gpio_leds_of_match, "lcd-cape-leds",
			"version", version);
	if (IS_ERR(info->leds_pdev)) {
		dev_err(&dev->dev, "Failed to create platform led "
				"platform device\n");
		err = PTR_ERR(info->leds_pdev);
		info->leds_pdev = NULL;
		goto err_no_leds_pdev;
	}

	dev_info(&dev->dev, "LED pdev created OK\n");

	if (match->data == BONE_LCD_TYPE(3) ||
			match->data == BONE_LCD_TYPE(4)) {
		info->bl_pdev = capebus_of_platform_compatible_device_create(
				dev, tps_bl_of_match, "lcd-cape-bl",
				"version", version);
		if (IS_ERR(info->bl_pdev)) {
			dev_warn(&dev->dev, "Failed to tps backlight "
					"platform device\n");
			err = PTR_ERR(info->bl_pdev);
			info->bl_pdev = NULL;
			goto err_no_bl_pdev;
		}
		dev_info(&dev->dev, "tps backlight pdev created OK\n");
	}

	info->keys_pdev = capebus_of_platform_compatible_device_create(dev,
			gpio_keys_of_match, "lcd-cape-keys",
			"version", version);
	if (IS_ERR(info->keys_pdev)) {
		dev_err(&dev->dev, "Failed to create platform gpio-keys "
				"platform device\n");
		err = PTR_ERR(info->keys_pdev);
		info->keys_pdev = NULL;
		goto err_no_keys_pdev;
	}

	dev_info(&dev->dev, "GPIO keys pdev created OK\n");

	info->tscadc_pdev = capebus_of_platform_compatible_device_create(dev,
			ti_tscadc_dt_of_match, "lcd-cape-ti-tscadc",
			"version", version);
	if (info->tscadc_pdev == NULL) {
		dev_err(&dev->dev, "Could not create tsc_adc device\n");
		err = -ENODEV;
		goto err_no_tsc_pdev;
	}

	dev_info(&dev->dev, "TI tscadc pdev created OK\n");

	info->da8xx_dt_pdev = capebus_of_platform_compatible_device_create(dev,
			da8xx_dt_of_match, "lcd-cape-da8xx",
			"version", version);
	if (IS_ERR(info->da8xx_dt_pdev)) {
		info->da8xx_dt_pdev = NULL;
		dev_err(&dev->dev, "Failed to create da8xx platform device\n");
		err = -ENODEV;
		goto err_no_da8xx_fb;
	}

	dev_info(&dev->dev, "da8xx-dt pdev created OK\n");

	return 0;

err_no_da8xx_fb:
	platform_device_unregister(info->tscadc_pdev);
err_no_tsc_pdev:
	platform_device_unregister(info->keys_pdev);
err_no_keys_pdev:
	platform_device_unregister(info->bl_pdev);
err_no_bl_pdev:
	platform_device_unregister(info->leds_pdev);
err_no_leds_pdev:
	devm_kfree(&dev->dev, info);
err_no_mem:
	return err;
}

static void bonelcd_remove(struct cape_dev *dev)
{
	dev_info(&dev->dev, "%s\n", __func__);
}

struct cape_driver bonelcd_driver = {
	.driver = {
		.name		= "bonelcd",
		.owner		= THIS_MODULE,
		.of_match_table	= bonelcd_of_match,
	},
	.probe		= bonelcd_probe,
	.remove		= bonelcd_remove,
};

module_capebus_driver(bonelcd_driver);

MODULE_AUTHOR("Pantelis Antoniou");
MODULE_DESCRIPTION("Beaglebone LCD cape");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:bone-lcd-cape");
