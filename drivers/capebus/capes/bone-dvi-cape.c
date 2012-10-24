/*
 * Driver for beaglebone DVI cape
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

#include <linux/capebus/capebus-bone.h>

/* fwd decl. */
extern struct cape_driver bonedvi_driver;

struct bone_dvi_info {
	struct cape_dev *dev;
	struct platform_device *leds_pdev;
	struct platform_device *da8xx_pdev;
};

static const struct of_device_id bonedvi_of_match[] = {
	{
		.compatible = "bone-dvi-cape",
	},
	{ },
};
MODULE_DEVICE_TABLE(of, bonedvi_of_match);

static int bonedvi_probe(struct cape_dev *dev, const struct cape_device_id *id)
{
	static const struct of_device_id gpio_leds_of_match[] = {
		{ .compatible = "gpio-leds", }, { },
	};
	static const struct of_device_id da8xx_dt_of_match[] = {
		{ .compatible = "da8xx-dt", }, { },
	};
	char boardbuf[33];
	char versionbuf[5];
	const char *board_name;
	const char *version;
	const struct of_device_id *match;
	struct bone_dvi_info *info;
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

	dev_info(&dev->dev, "%s: V=%s initialized - '%s'\n", board_name,
			version, match->compatible);

	dev->drv_priv = devm_kzalloc(&dev->dev, sizeof(*info), GFP_KERNEL);
	if (dev->drv_priv == NULL) {
		dev_err(&dev->dev, "Failed to allocate info\n");
		err = -ENOMEM;
		goto err_no_mem;
	}
	info = dev->drv_priv;

	info->leds_pdev = capebus_of_platform_compatible_device_create(dev,
			gpio_leds_of_match, "dvi-cape-leds",
			"version", version);
	if (IS_ERR(info->leds_pdev)) {
		info->leds_pdev = NULL;
		dev_err(&dev->dev, "Failed to create platform led "
				"platform device\n");
		err = -ENODEV;
		goto err_no_leds_pdev;
	}

	dev_info(&dev->dev, "LED pdev created OK\n");

	info->da8xx_pdev = capebus_of_platform_compatible_device_create(dev,
			da8xx_dt_of_match, "dvi-cape-da8xx",
			"version", version);
	if (IS_ERR(info->da8xx_pdev)) {
		info->da8xx_pdev = NULL;
		dev_err(&dev->dev, "Failed to create da8xx platform device\n");
		err = -ENODEV;
		goto err_no_da8xx_fb;
	}

	dev_info(&dev->dev, "da8xx-dt pdev created OK\n");

	return 0;

err_no_da8xx_fb:
	platform_device_unregister(info->leds_pdev);
err_no_leds_pdev:
	devm_kfree(&dev->dev, info);
err_no_mem:
	return err;
}

static void bonedvi_remove(struct cape_dev *dev)
{
	dev_info(&dev->dev, "%s\n", __func__);
}

struct cape_driver bonedvi_driver = {
	.driver = {
		.name		= "bonedvi",
		.owner		= THIS_MODULE,
		.of_match_table	= bonedvi_of_match,
	},
	.probe		= bonedvi_probe,
	.remove		= bonedvi_remove,
};

module_capebus_driver(bonedvi_driver);

MODULE_AUTHOR("Pantelis Antoniou");
MODULE_DESCRIPTION("Beaglebone DVI cape");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:bone-dvi-cape");
