/*
 * drivers/capebus/capebus-sysfs.c
 *
 * sysfs for capebus devices
 *
 * Copyright (C) 2012 Pantelis Antoniou <panto@antoniou-consulting.com>
 * Copyright (C) 2012 Texas Instruments Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Modeled after PCI's pci-sysfs.c
 *
 */

#include <linux/kernel.h>
#include <linux/stat.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pm_runtime.h>

#include <linux/capebus.h>

static ssize_t is_enabled_store(struct device *dev,
				struct device_attribute *attr, const char *buf,
				size_t count)
{
	struct cape_dev *cdev = to_cape_dev(dev);
	unsigned long val;
	ssize_t result = strict_strtoul(buf, 0, &val);

	if (result < 0)
		return result;

	/* this can crash the machine when done on the "wrong" device */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!val) {
		if (capebus_is_enabled(cdev))
			capebus_disable_device(cdev);
		else
			result = -EIO;
	} else
		result = capebus_enable_device(cdev);

	return result < 0 ? result : count;
}

static ssize_t is_enabled_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct cape_dev *cdev;

	cdev = to_cape_dev(dev);
	return sprintf(buf, "%u\n", atomic_read(&cdev->enable_cnt));
}

static ssize_t id_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct cape_dev *cdev;

	cdev = to_cape_dev(dev);
	return sprintf(buf, "%s\n", cdev->text_id);
}

struct device_attribute capebus_dev_attrs[] = {
	__ATTR(enable, 0600, is_enabled_show, is_enabled_store),
	__ATTR(id, 0400, id_show, NULL),
	__ATTR_NULL,
};

struct bus_attribute capebus_bus_attrs[] = {
	__ATTR_NULL
};
