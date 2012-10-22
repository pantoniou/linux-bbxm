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
#include <video/da8xx-fb.h>
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

struct da8xx_priv {
	int power_dn_gpio;
	struct da8xx_lcdc_platform_data dvi_pdata;
	struct lcd_ctrl_config dvi_cfg;
	struct display_panel dvi_panel;
	struct platform_device *lcdc_pdev;
	struct omap_hwmod *lcdc_oh;
	struct resource lcdc_res[1];
};

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

static const struct of_device_id of_da8xx_dt_match[] = {
	{ .compatible = "da8xx-dt", },
	{},
};

static int __devinit da8xx_dt_probe(struct platform_device *pdev)
{
	struct da8xx_priv *priv;
	struct clk *disp_pll;
	struct pinctrl *pinctrl;
	int ret = -EINVAL;

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	if (priv == NULL) {
		dev_err(&pdev->dev, "Failed to allocate priv\n");
		return -ENOMEM;
	}

	pinctrl = devm_pinctrl_get_select_default(&pdev->dev);
	if (IS_ERR(pinctrl))
		dev_warn(&pdev->dev,
			"pins are not configured from the driver\n");

	/* conf_disp_pll(560000000); */
	disp_pll = clk_get(NULL, "dpll_disp_ck");
	if (IS_ERR(disp_pll)) {
		dev_err(&pdev->dev, "Cannot clk_get disp_pll\n");
		return PTR_ERR(disp_pll);
	}
	ret = clk_set_rate(disp_pll, 560000000);
	clk_put(disp_pll);
	if (ret != 0) {
		dev_err(&pdev->dev, "Failed to set disp_pll\n");
		return ret;
	}

	ret = of_get_named_gpio_flags(pdev->dev.of_node, "powerdn-gpio",
			0, NULL);
	if (IS_ERR_VALUE(ret)) {
		dev_err(&pdev->dev, "Failed to get power down GPIO\n");
		return ret;
	}
	priv->power_dn_gpio = ret;

	ret = gpio_request(priv->power_dn_gpio, "bone-dvi-cape:DVI_PDN");
	if (ret != 0) {
		dev_err(&pdev->dev, "Failed to gpio_request\n");
		return ret;
	}

	ret = gpio_direction_output(priv->power_dn_gpio, 1);
	if (ret != 0) {
		dev_err(&pdev->dev, "Failed to set powerdn to 1\n");
		return ret;
	}

	/* display_panel */
	priv->dvi_panel.panel_type	= QVGA;
	priv->dvi_panel.max_bpp		= 16;
	priv->dvi_panel.min_bpp		= 16;
	priv->dvi_panel.panel_shade	= COLOR_ACTIVE;

	/* lcd_ctrl_config */
	priv->dvi_cfg.p_disp_panel	= &priv->dvi_panel;
	priv->dvi_cfg.ac_bias		= 255;
	priv->dvi_cfg.ac_bias_intrpt	= 0;
	priv->dvi_cfg.dma_burst_sz	= 16;
	priv->dvi_cfg.bpp		= 16;
	priv->dvi_cfg.fdd		= 0x80;
	priv->dvi_cfg.tft_alt_mode	= 0;
	priv->dvi_cfg.stn_565_mode	= 0;
	priv->dvi_cfg.mono_8bit_mode	= 0;
	priv->dvi_cfg.invert_line_clock	= 1;
	priv->dvi_cfg.invert_frm_clock	= 1;
	priv->dvi_cfg.sync_edge		= 0;
	priv->dvi_cfg.sync_ctrl		= 1;
	priv->dvi_cfg.raster_order	= 0;

	/* da8xx_lcdc_platform_data */
	strcpy(priv->dvi_pdata.manu_name, "BBToys");
	priv->dvi_pdata.controller_data	= &priv->dvi_cfg;
	strcpy(priv->dvi_pdata.type, "1024x768@60");

	priv->lcdc_oh = omap_hwmod_lookup("lcdc");
	if (priv->lcdc_oh == NULL) {
		dev_err(&pdev->dev, "Failed to lookup omap_hwmod lcdc\n");
		return -ENODEV;
	}

	priv->lcdc_pdev = omap_device_build("da8xx_lcdc", 0, priv->lcdc_oh,
			&priv->dvi_pdata,
			sizeof(struct da8xx_lcdc_platform_data),
			NULL, 0, 0);
	if (priv->lcdc_pdev == NULL) {
		dev_err(&pdev->dev, "Failed to build LCDC device\n");
		return -ENODEV;
	}

	dev_info(&pdev->dev, "Registered bone DVI cape OK.\n");

	platform_set_drvdata(pdev, priv);

	return 0;
}

static int __devexit da8xx_dt_remove(struct platform_device *pdev)
{
	return -EINVAL;	/* not supporting removal yet */
}

static struct platform_driver da8xx_dt_driver = {
	.probe		= da8xx_dt_probe,
	.remove		= __devexit_p(da8xx_dt_remove),
	.driver		= {
		.name	= "da8xx-dt",
		.owner	= THIS_MODULE,
		.of_match_table = of_da8xx_dt_match,
	},
};

static atomic_t da8xx_dt_driver_used = ATOMIC_INIT(0);

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

	smp_mb();
	if (atomic_inc_return(&da8xx_dt_driver_used) == 1) {
		smp_mb();
		err = platform_driver_register(&da8xx_dt_driver);
		if (err != 0) {
			dev_err(&dev->dev, "Failed to register da8xx_dt "
					"platform driver\n");
			return -ENODEV;
		}
	}
	smp_mb();

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
	smp_mb();
	if (atomic_dec_return(&da8xx_dt_driver_used) == 0) {
		smp_mb();
		platform_driver_unregister(&da8xx_dt_driver);
	}
	smp_mb();
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
