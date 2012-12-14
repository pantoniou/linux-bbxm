/*
 * Utility functions for working with device tree(s)
 *
 * Copyright (C) 2012 Pantelis Antoniou <panto@antoniou-consulting.com>
 * Copyright (C) 2012 Texas Instruments Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/err.h>

/* only call on known allocated properties */
void __of_free_property(struct property *prop)
{
	if (prop == NULL)
		return;

	if (of_property_check_flag(prop, OF_DYNAMIC)) {
		kfree(prop->value);
		kfree(prop->name);
		kfree(prop);
	} else {
		pr_warn("%s: property %p cannot be freed; memory is gone\n", 
				__func__, prop);
	}
}

/* make sure this is a detached node before calling it */
void __of_free_tree(struct device_node *node)
{
	struct property *prop;
	struct device_node *noden;

	/* make sure this is a dynamic detached node */
	if (!node)
		return;

	/* free recursively any children */
	while ((noden = node->child) != NULL) {
		node->child = noden->sibling;
		__of_free_tree(noden);
	}

	/* free every property already allocated */
	while ((prop = node->properties) != NULL) {
		node->properties = prop->next;
		__of_free_property(prop);
	}

	/* free dead properties already allocated */
	while ((prop = node->deadprops) != NULL) {
		node->deadprops = prop->next;
		__of_free_property(prop);
	}

	if (of_node_check_flag(node, OF_DYNAMIC)) {
		kfree(node->type);
		kfree(node->name);
		kfree(node);
	} else {
		pr_warn("%s: node %p cannot be freed; memory is gone\n", 
				__func__, node);
	}
}

struct property *__of_copy_property(const struct property *prop, gfp_t flags)
{
	struct property *propn;

	propn = kzalloc(sizeof(*prop), flags);
	if (propn == NULL)
		return NULL;

	propn->name = kstrdup(prop->name, flags);
	if (propn->name == NULL)
		goto err_fail_name;

	if (prop->length > 0) {
		propn->value = kmalloc(prop->length, flags);
		if (propn->value == NULL)
			goto err_fail_value;
		memcpy(propn->value, prop->value, prop->length);
		propn->length = prop->length;
	}

	/* mark the property as dynamic */
	of_property_set_flag(propn, OF_DYNAMIC);

	return propn;

err_fail_value:
	kfree(propn->name);
err_fail_name:
	kfree(propn);
	return NULL;
}

struct device_node *__of_create_empty_node(
		const char *name, const char *type, const char *full_name,
		phandle phandle, gfp_t flags)
{
	struct device_node *node;

	node = kzalloc(sizeof(*node), flags);
	if (node == NULL)
		return NULL;

	node->name = kstrdup(name, flags);
	if (node->name == NULL)
		goto err_return;

	node->type = kstrdup(type, flags);
	if (node->type == NULL)
		goto err_return;

	node->full_name = kstrdup(full_name, flags);
	if (node->type == NULL)
		goto err_return;

	node->phandle = phandle;
	kref_init(&node->kref);
	of_node_set_flag(node, OF_DYNAMIC);
	of_node_set_flag(node, OF_DETACHED);

	return node;

err_return:
	__of_free_tree(node);
	return NULL;
}

int of_multi_prop_cmp(const struct property *prop, const char *value)
{
	const char *cp;
	int cplen, vlen, l;

	if (prop == NULL || value == NULL)
		return -1;

	cp = prop->value;
	cplen = prop->length;
	vlen = strlen(value);

	while (cplen > 0) {
		if (of_compat_cmp(cp, value, vlen) == 0)
			return 0;
		l = strlen(cp) + 1;
		cp += l;
		cplen -= l;
	}

	return -1;
}
