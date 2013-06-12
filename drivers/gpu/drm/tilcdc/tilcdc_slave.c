/*
 * Copyright (C) 2012 Texas Instruments
 * Author: Rob Clark <robdclark@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/i2c.h>
#include <linux/of_i2c.h>
#include <linux/pinctrl/pinmux.h>
#include <linux/pinctrl/consumer.h>
#include <drm/drm_encoder_slave.h>

#include "tilcdc_drv.h"

/* keep a list of text modestrings */
struct slave_modelist {
	struct list_head node;
	const char *modestr;		/* the text mode string i.e. 1280x720@50 */
	struct drm_cmdline_mode clmode;	/* the command line mode */
	struct drm_display_mode *mode;	/* the display mode (as seen by the device) */
	unsigned int parsed : 1;	/* parsed (whether good or bad) */
	unsigned int good : 1;		/* it's ok to use it */
};

struct slave_module {
	struct tilcdc_module base;
	struct tilcdc_panel_info *info;
	struct i2c_adapter *i2c;
	struct list_head whitelist;
	struct list_head blacklist;
};
#define to_slave_module(x) container_of(x, struct slave_module, base)

/*
 * Encoder:
 */

struct slave_encoder {
	struct drm_encoder_slave base;
	struct slave_module *mod;
};
#define to_slave_encoder(x) container_of(to_encoder_slave(x), struct slave_encoder, base)

static inline struct drm_encoder_slave_funcs *
get_slave_funcs(struct drm_encoder *enc)
{
	return to_encoder_slave(enc)->slave_funcs;
}

static void slave_encoder_destroy(struct drm_encoder *encoder)
{
	struct slave_encoder *slave_encoder = to_slave_encoder(encoder);
	if (get_slave_funcs(encoder))
		get_slave_funcs(encoder)->destroy(encoder);
	drm_encoder_cleanup(encoder);
	kfree(slave_encoder);
}

static void slave_encoder_prepare(struct drm_encoder *encoder)
{
	struct slave_encoder *slave_encoder = to_slave_encoder(encoder);

	drm_i2c_encoder_prepare(encoder);
	tilcdc_crtc_set_panel_info(encoder->crtc, slave_encoder->mod->info);
}

static bool slave_encoder_fixup(struct drm_encoder *encoder,
		const struct drm_display_mode *mode,
		struct drm_display_mode *adjusted_mode)
{
	adjusted_mode->hskew = mode->hsync_end - mode->hsync_start;
	adjusted_mode->flags |= DRM_MODE_FLAG_HSKEW;

	if(mode->flags & DRM_MODE_FLAG_NHSYNC) {
		adjusted_mode->flags |= DRM_MODE_FLAG_PHSYNC;
		adjusted_mode->flags &= ~DRM_MODE_FLAG_NHSYNC;
	} else {
		adjusted_mode->flags |= DRM_MODE_FLAG_NHSYNC;
		adjusted_mode->flags &= ~DRM_MODE_FLAG_PHSYNC;
	}

	return drm_i2c_encoder_mode_fixup(encoder, mode, adjusted_mode);
}


static const struct drm_encoder_funcs slave_encoder_funcs = {
		.destroy        = slave_encoder_destroy,
};

static const struct drm_encoder_helper_funcs slave_encoder_helper_funcs = {
		.dpms           = drm_i2c_encoder_dpms,
		.mode_fixup     = slave_encoder_fixup,
		.prepare        = slave_encoder_prepare,
		.commit         = drm_i2c_encoder_commit,
		.mode_set       = drm_i2c_encoder_mode_set,
		.save           = drm_i2c_encoder_save,
		.restore        = drm_i2c_encoder_restore,
};

static const struct i2c_board_info info = {
		I2C_BOARD_INFO("tda998x", 0x70)
};

static struct drm_encoder *slave_encoder_create(struct drm_device *dev,
		struct slave_module *mod)
{
	struct slave_encoder *slave_encoder;
	struct drm_encoder *encoder;
	int ret;

	slave_encoder = kzalloc(sizeof(*slave_encoder), GFP_KERNEL);
	if (!slave_encoder) {
		dev_err(dev->dev, "allocation failed\n");
		return NULL;
	}

	slave_encoder->mod = mod;

	encoder = &slave_encoder->base.base;
	encoder->possible_crtcs = 1;

	ret = drm_encoder_init(dev, encoder, &slave_encoder_funcs,
			DRM_MODE_ENCODER_TMDS);
	if (ret)
		goto fail;

	drm_encoder_helper_add(encoder, &slave_encoder_helper_funcs);

	ret = drm_i2c_encoder_init(dev, to_encoder_slave(encoder), mod->i2c, &info);
	if (ret)
		goto fail;

	return encoder;

fail:
	slave_encoder_destroy(encoder);
	return NULL;
}

/*
 * Connector:
 */

struct slave_connector {
	struct drm_connector base;

	struct drm_encoder *encoder;  /* our connected encoder */
	struct slave_module *mod;
};
#define to_slave_connector(x) container_of(x, struct slave_connector, base)

static void slave_connector_destroy(struct drm_connector *connector)
{
	struct slave_connector *slave_connector = to_slave_connector(connector);
	drm_connector_cleanup(connector);
	kfree(slave_connector);
}

static enum drm_connector_status slave_connector_detect(
		struct drm_connector *connector,
		bool force)
{
	struct drm_encoder *encoder = to_slave_connector(connector)->encoder;
	return get_slave_funcs(encoder)->detect(encoder, connector);
}

static int slave_connector_get_modes(struct drm_connector *connector)
{
	struct drm_encoder *encoder = to_slave_connector(connector)->encoder;
	return get_slave_funcs(encoder)->get_modes(encoder, connector);
}

static int slave_modelist_match(struct drm_connector *connector,
		struct slave_modelist *sml, struct drm_display_mode *mode)
{
	struct drm_cmdline_mode *clmode = &sml->clmode;

	if (sml->mode == NULL || !sml->good)
		return 0;

	/* xres, yres valid */
	if (clmode->specified &&
		(drm_mode_width(mode) != clmode->xres ||
			drm_mode_height(mode) != clmode->yres))
		return 0;

	/* refresh mode specified */
	if (clmode->refresh_specified &&
		drm_mode_vrefresh(mode) != clmode->refresh)
		return 0;

	/* interlace */
	if (clmode->interlace && (mode->flags & DRM_MODE_FLAG_INTERLACE) == 0)
		return 0;

	/* match */
	return 1;
}

/* returns 0 if mode is listed, -ENOENT otherwise */
static int slave_connector_mode_match(struct drm_connector *connector,
		struct drm_display_mode *mode,
		struct list_head *lh)
{
	struct drm_device *dev = connector->dev;
	struct slave_modelist *sml;
	bool parse;

	/* ok, we have to find a match */
	list_for_each_entry(sml, lh, node) {

		/* if the mode is not parsed, do it now */
		if (!sml->parsed) {

			/* whether good or bad, we're trying only once */
			sml->parsed = 1;
			sml->good = 0;

			parse = drm_mode_parse_command_line_for_connector(
					sml->modestr, connector, &sml->clmode);

			/* report in case something's off */
			if (!parse) {
				dev_err(dev->dev, "Failed to parse mode %s\n",
						sml->modestr);
				continue;
			}

			/* need to hold the mutex */
			mutex_lock(&dev->mode_config.mutex);
			sml->mode = drm_mode_create_from_cmdline_mode(dev,
					&sml->clmode);
			mutex_unlock(&dev->mode_config.mutex);

			if (sml->mode == NULL) {
				dev_err(dev->dev, "Failed to create mode %s\n",
						sml->modestr);
				continue;
			}
			sml->good = 1;
		}

		/* bad mode is skipped */
		if (!sml->good)
			continue;

		/* we can't use drm_mode_equal, we use own own comparison */
		if (slave_modelist_match(connector, sml, mode)) {
			return 1;
		}

	}

	return 0;
}

static int slave_connector_mode_whitelisted(struct drm_connector *connector,
		struct drm_display_mode *mode)
{
	struct slave_connector *slave_connector = to_slave_connector(connector);
	struct slave_module *slave_mod = slave_connector->mod;
	int ret;

	/* if the list is empty, everything is whitelisted */
	if (list_empty(&slave_mod->whitelist))
		return 1;

	ret = slave_connector_mode_match(connector, mode, &slave_mod->whitelist);
	if (ret != 0)
		return 1;

	/* not found */
	return 0;
}

static int slave_connector_mode_blacklisted(struct drm_connector *connector,
		struct drm_display_mode *mode)
{
	struct slave_connector *slave_connector = to_slave_connector(connector);
	struct slave_module *slave_mod = slave_connector->mod;
	int ret;

	/* if the list is empty, nothing is blacklisted */
	if (list_empty(&slave_mod->blacklist))
		return 0;

	ret = slave_connector_mode_match(connector, mode, &slave_mod->blacklist);
	if (ret != 0)
		return 1;

	/* not found; all is OK */
	return 0;
}

static int slave_connector_mode_valid(struct drm_connector *connector,
		  struct drm_display_mode *mode)
{
	struct drm_encoder *encoder = to_slave_connector(connector)->encoder;
	struct drm_device *dev = connector->dev;
	struct tilcdc_drm_private *priv = dev->dev_private;
	int ret;

	/* if there's a whitelist, we must be in it */
	if (!slave_connector_mode_whitelisted(connector, mode)) {
		dev_info(dev->dev, "mode %dx%d@%d is not whitelisted\n",
			drm_mode_width(mode), drm_mode_height(mode),
			drm_mode_vrefresh(mode));
		return MODE_BAD;
	}

	/* if there's a blacklist, we shouldn't be in it */
	if (slave_connector_mode_blacklisted(connector, mode)) {
		dev_info(dev->dev, "mode %dx%d@%d is blacklisted\n",
			drm_mode_width(mode), drm_mode_height(mode),
			drm_mode_vrefresh(mode));
		return MODE_BAD;
	}

	ret = tilcdc_crtc_mode_valid(priv->crtc, mode,
			priv->allow_non_rblank ? 0 : 1,
			priv->allow_non_audio ? 0 : 1,
			connector->edid_blob_ptr ?
				(struct edid *)connector->edid_blob_ptr->data :
				NULL);
	if (ret != MODE_OK)
		return ret;

	return get_slave_funcs(encoder)->mode_valid(encoder, mode);
}

static struct drm_encoder *slave_connector_best_encoder(
		struct drm_connector *connector)
{
	struct slave_connector *slave_connector = to_slave_connector(connector);
	return slave_connector->encoder;
}

static int slave_connector_set_property(struct drm_connector *connector,
		struct drm_property *property, uint64_t value)
{
	struct drm_encoder *encoder = to_slave_connector(connector)->encoder;
	return get_slave_funcs(encoder)->set_property(encoder,
			connector, property, value);
}

static const struct drm_connector_funcs slave_connector_funcs = {
	.destroy            = slave_connector_destroy,
	.dpms               = drm_helper_connector_dpms,
	.detect             = slave_connector_detect,
	.fill_modes         = drm_helper_probe_single_connector_modes,
	.set_property       = slave_connector_set_property,
};

static const struct drm_connector_helper_funcs slave_connector_helper_funcs = {
	.get_modes          = slave_connector_get_modes,
	.mode_valid         = slave_connector_mode_valid,
	.best_encoder       = slave_connector_best_encoder,
};

static struct drm_connector *slave_connector_create(struct drm_device *dev,
		struct slave_module *mod, struct drm_encoder *encoder)
{
	struct slave_connector *slave_connector;
	struct drm_connector *connector;
	int ret;

	slave_connector = kzalloc(sizeof(*slave_connector), GFP_KERNEL);
	if (!slave_connector) {
		dev_err(dev->dev, "allocation failed\n");
		return NULL;
	}

	slave_connector->encoder = encoder;
	slave_connector->mod = mod;

	connector = &slave_connector->base;

	drm_connector_init(dev, connector, &slave_connector_funcs,
			DRM_MODE_CONNECTOR_HDMIA);
	drm_connector_helper_add(connector, &slave_connector_helper_funcs);

	connector->polled = DRM_CONNECTOR_POLL_CONNECT |
			DRM_CONNECTOR_POLL_DISCONNECT;

	connector->interlace_allowed = 0;
	connector->doublescan_allowed = 0;

	get_slave_funcs(encoder)->create_resources(encoder, connector);

	ret = drm_mode_connector_attach_encoder(connector, encoder);
	if (ret)
		goto fail;

	drm_sysfs_connector_add(connector);

	return connector;

fail:
	slave_connector_destroy(connector);
	return NULL;
}

/*
 * Module:
 */

static int slave_modeset_init(struct tilcdc_module *mod, struct drm_device *dev)
{
	struct slave_module *slave_mod = to_slave_module(mod);
	struct tilcdc_drm_private *priv = dev->dev_private;
	struct drm_encoder *encoder;
	struct drm_connector *connector;

	if (priv->num_encoders >= ARRAY_SIZE(priv->encoders))
		return -ENOENT;

	if (priv->num_connectors >= ARRAY_SIZE(priv->connectors))
		return -ENOENT;

	encoder = slave_encoder_create(dev, slave_mod);
	if (!encoder)
		return -ENOMEM;

	connector = slave_connector_create(dev, slave_mod, encoder);
	if (!connector)
		return -ENOMEM;

	priv->encoders[priv->num_encoders++] = encoder;
	priv->connectors[priv->num_connectors++] = connector;

	return 0;
}

static void slave_destroy(struct tilcdc_module *mod, struct drm_device *dev)
{
	struct slave_module *slave_mod = to_slave_module(mod);
	struct slave_modelist *sml;

	tilcdc_module_cleanup(mod);

	if (dev != NULL) {
		/* no need to free sml, it's res tracked */
		list_for_each_entry(sml, &slave_mod->whitelist, node) {
			if (sml->mode != NULL)
				drm_mode_destroy(dev, sml->mode);
		}

		list_for_each_entry(sml, &slave_mod->whitelist, node) {
			if (sml->mode != NULL)
				drm_mode_destroy(dev, sml->mode);
		}
	}

	kfree(slave_mod->info);
	kfree(slave_mod);
}

static const struct tilcdc_module_ops slave_module_ops = {
	.modeset_init = slave_modeset_init,
	.destroy = slave_destroy,
};

/*
 * Device:
 */

static struct of_device_id slave_of_match[];

/* fill in the mode list via the string list property */
static int slave_mode_of_mode_list(struct platform_device *pdev,
		const char *propname, struct list_head *lh)
{
	struct device *dev = &pdev->dev;
	struct device_node *node = dev->of_node;
	struct slave_modelist *sml;
	int ret, i, count;

	/* count the string list property */
	count = of_property_count_strings(node, propname);

	/* negative or zero, means no mode list */
	if (count <= 0)
		return 0;

	for (i = 0; i < count; i++) {

		sml = devm_kzalloc(dev, sizeof(*sml), GFP_KERNEL);
		if (sml == NULL) {
			dev_err(dev, "Failed to allocate mode list for %s\n",
					propname);
			return -ENOMEM;
		}

		ret = of_property_read_string_index(node, propname, i,
				&sml->modestr);
		if (ret != 0) {
			dev_err(dev, "Failed to read string #%d for %s \n",
					i, propname);
			return ret;
		}

		/* add it to the tail */
		list_add_tail(&sml->node, lh);

		dev_info(dev, "%s #%d -> %s\n",
				propname, i, sml->modestr);

	}

	return 0;
}

static int slave_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *node = dev->of_node;
	struct device_node *i2c_node;
	struct slave_module *slave_mod;
	struct tilcdc_module *mod;
	struct pinctrl *pinctrl;
	uint32_t i2c_phandle;
	struct i2c_adapter *slavei2c;
	int ret = -EINVAL;

	/* bail out early if no DT data: */
	if (!node) {
		dev_err(&pdev->dev, "device-tree data is missing\n");
		return -ENXIO;
	}

	/* Bail out early if i2c not specified */
	if (of_property_read_u32(node, "i2c", &i2c_phandle)) {
		dev_err(&pdev->dev, "could not get i2c bus phandle\n");
		return ret;
	}

	i2c_node = of_find_node_by_phandle(i2c_phandle);
	if (!i2c_node) {
		dev_err(&pdev->dev, "could not get i2c bus node\n");
		return ret;
	}

	/* but defer the probe if it can't be initialized it might come later */
	slavei2c = of_find_i2c_adapter_by_node(i2c_node);
	of_node_put(i2c_node);

	if (!slavei2c) {
		ret = -EPROBE_DEFER;
		tilcdc_slave_probedefer(true);
		dev_err(&pdev->dev, "could not get i2c\n");
		return ret;
	}

	slave_mod = devm_kzalloc(&pdev->dev, sizeof(*slave_mod), GFP_KERNEL);
	if (!slave_mod)
		return -ENOMEM;

	platform_set_drvdata(pdev, slave_mod);

	INIT_LIST_HEAD(&slave_mod->whitelist);
	INIT_LIST_HEAD(&slave_mod->blacklist);

	mod = &slave_mod->base;
	slave_mod->info = tilcdc_of_get_panel_info(node);
	if (!slave_mod->info) {
		dev_err(&pdev->dev, "could not get panel info\n");
		return -ENODEV;
	}

	ret = slave_mode_of_mode_list(pdev, "modes-blacklisted",
			&slave_mod->blacklist);
	if (ret != 0) {
		dev_err(&pdev->dev, "Invalid modes-blacklisted property\n");
		return ret;
	}

	ret = slave_mode_of_mode_list(pdev, "modes-whitelisted",
			&slave_mod->whitelist);
	if (ret != 0) {
		dev_err(&pdev->dev, "Invalid modes-whitelisted property\n");
		return ret;
	}

	of_node_put(i2c_node);

	mod->preferred_bpp = /* slave_info.bpp */ 16;

	slave_mod->i2c = slavei2c;

	tilcdc_module_init(mod, "slave", &slave_module_ops);

	pinctrl = devm_pinctrl_get_select_default(&pdev->dev);
	if (IS_ERR(pinctrl))
		dev_warn(&pdev->dev, "pins are not configured\n");

	tilcdc_slave_probedefer(false);

	return 0;
}

static int slave_remove(struct platform_device *pdev)
{
	return 0;
}

static struct of_device_id slave_of_match[] = {
		{ .compatible = "ti,tilcdc,slave", },
		{ .compatible = "tilcdc,slave", },
		{ },
};

struct platform_driver slave_driver = {
	.probe = slave_probe,
	.remove = slave_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = "slave",
		.of_match_table = slave_of_match,
	},
};

int __init tilcdc_slave_init(void)
{
	return platform_driver_register(&slave_driver);
}

void __exit tilcdc_slave_fini(void)
{
	platform_driver_unregister(&slave_driver);
}
