/*
 * Functions for working with device tree overlays
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

/* applies the overlay to the target node destructively */
int __of_apply_tree_overlay(
		struct device_node *target,
		const struct device_node *overlay,
		struct device_node **allp)
{
	const char *pname, *cname;
	struct device_node *child, *tchild, **tchildp, **nodep;
	struct property *prop, *propn, *tprop, **tpropp;
	int found, remove;
	char *full_name;
	const char *suffix;
	int ret;

	/* sanity checks */
	if (target == NULL || allp == NULL)
		return -EINVAL;

	/* possible when just copying */
	if (overlay == NULL)
		goto skip_overlay;

	__for_each_property_of_node(overlay, prop) {

		/* don't touch, 'name' */
		if (of_prop_cmp(prop->name, "name") == 0)
			continue;

		/* default is add */
		remove = 0;
		pname = prop->name;
		if (*pname == '-') {	/* skip, - notes removal */
			pname++;
			remove = 1;
		}

		/* iterate over each property of target */
		found = 0;
		tpropp = &target->properties;
		__for_each_property_of_node(target, tprop) {

			if (of_prop_cmp(tprop->name, pname) == 0) {

				if (!remove) {
					/* add directly here */

					propn = __of_copy_property(prop,
							GFP_KERNEL);
					if (propn == NULL)
						return -ENOMEM;

					/* replace */
					*tpropp = propn;
					propn->next = tprop->next;

				} else {
					/* remove it */
					*tpropp = tprop->next;
				}

				/* free the property replaced or removed */
				if (of_node_check_flag(target, OF_DYNAMIC)) {
					__of_free_property(tprop);
				} else {
					/* node not dynamic, move to deadprop */
					tprop->next = target->deadprops;
					target->deadprops = tprop;
				}

				found = 1;
				break;
			}
			tpropp = &tprop->next;
		}

		/* not found and needs to be added */
		if (!found && !remove) {

			/* create property */
			propn = __of_copy_property(prop, GFP_KERNEL);
			if (propn == NULL) 
				return -ENOMEM;

			/* append it at the end */
			*tpropp = propn;
		}
	}

	__for_each_child_of_node(overlay, child) {

		/* default is add */
		remove = 0;
		cname = child->name;
		if (*cname == '-') {	/* skip, - notes removal */
			cname++;
			remove = 1;
		}

		found = 0;
		tchildp = &target->child;
		__for_each_child_of_node(target, tchild) {

			if (of_node_cmp(tchild->name, cname) == 0) {
				if (!remove) {
					/* apply overlay */
					ret = __of_apply_tree_overlay(tchild,
							child, allp);
					if (ret != 0)
						return ret;
				} else {
					/* remove it */
					*tchildp = tchild->next;
				}

				found = 1;
				break;
			}
			tchildp = &tchild->sibling;
		}

		/* not found, and not removed */
		if (!found && !remove) {

			/* locate the suffix on the full name (if it's there) */
			suffix = strrchr(target->full_name, '@');

			full_name = kasprintf(GFP_KERNEL, "%s/%s%s",
					target->full_name, child->name,
					suffix ? suffix : "");
			if (full_name == NULL)
				return -ENOMEM;

			/* create empty tree as a target */
			tchild = __of_create_empty_node(child->name,
					child->type, full_name,
					child->phandle, GFP_KERNEL);

			/* free either way */
			kfree(full_name);

			if (tchild == NULL)
				return -ENOMEM;

			/* apply the overlay */
			if (__of_apply_tree_overlay(tchild, child, allp) != 0)
				return -ENOMEM;
			
			/* add new child to the target */
			*tchildp = tchild;

			/* add it to allp (at the tail) */
			nodep = allp;
			while ((*nodep) != NULL)
				nodep = &(*nodep)->allnext;
			*nodep = tchild;

			/* link to parent */
			tchild->parent = target;

		} else if (found && remove) {

			/* find it and remove it */
			nodep = allp;
			while ((*nodep) != NULL) {
				if ((*nodep) == tchild)
					break;
				nodep = &(*nodep)->allnext;
			}
			if ((*nodep) == NULL)
				return -EINVAL;
			*nodep = tchild->allnext;

			/* free the child */
			__of_free_tree(tchild);
		}
	}

skip_overlay:

	/* link in any target nodes not affected by the overlay */
	__for_each_child_of_node(target, tchild) {

		found = 0;
		if (overlay != NULL) {
			__for_each_child_of_node(overlay, child) {
				cname = child->name;
				if (*cname == '-') 	/* skip, - =removal */
					cname++;
				if (of_node_cmp(tchild->name, cname) == 0) {
					found = 1;
					break;
				}
			}
		}

		if (!found) {
			ret = __of_apply_tree_overlay(tchild, NULL, allp);
			if (ret != 0)
				return ret;
		}
	}

	return 0;
}

/* new_node is on allnodes, old_node is detached */
void of_apply_overlay_post(struct device_node *old_node,
		struct device_node *new_node)
{
	struct device_node *old_child, *new_child;
	struct platform_device *pdev, *parent_pdev;
	int prev_status, new_status;

	/* a NULL node means the status is 0 */
	prev_status = old_node && of_device_is_available(old_node);
	new_status = new_node && of_device_is_available(new_node);

	/* pr_info("%s: old=%s new=%s\n", __func__,
			old_node ? old_node->full_name : "<NULL>",
			new_node ? new_node->full_name : "<NULL>"); */

	/* change from 0 -> 1; enable the parent first */
	if (prev_status == 0 && prev_status != new_status) {

		parent_pdev = of_find_device_by_node(new_node->parent);

		/* pr_info("%s: creating new platform device new_node='%s' %p\n",
				__func__, new_node->full_name, new_node); */

		pdev = of_platform_device_create(new_node, NULL,
				parent_pdev ? &parent_pdev->dev : NULL);
		if (pdev == NULL) {
			platform_device_put(parent_pdev);
			pr_err("%s: Failed to create pdev for '%s'\n",
					__func__, new_node->full_name);
		}
	}

	if (old_node && new_node) {

		/* first do the nodes that exist on both, or only on old_node */
		for_each_child_of_node(old_node, old_child) {

			for_each_child_of_node(new_node, new_child) {

				if (of_node_cmp(old_child->full_name,
						new_child->full_name) == 0) {

					of_apply_overlay_post(
							old_child, new_child);
					break;
				}
			}

			/* old_node exists, but not new_child */
			if (new_child == NULL)
				of_apply_overlay_post(old_child, NULL);
		}

		/* now do the nodes that exist only on new_node */
		for_each_child_of_node(new_node, new_child) {

			for_each_child_of_node(old_node, old_child) {

				if (of_node_cmp(old_child->full_name,
						new_child->full_name) == 0) {

					break;
				}
			}

			if (old_child == NULL)
				of_apply_overlay_post(NULL, new_child);
		}

	} else if (old_node) {

		for_each_child_of_node(old_node, old_child)
			of_apply_overlay_post(old_child, NULL);

	} else if (new_node) {

		for_each_child_of_node(new_node, new_child)
			of_apply_overlay_post(NULL, new_child);
	}

	/* change from 1 -> 0; disable the parent last */
	if (prev_status == 1 && prev_status != new_status) {

		pdev = of_find_device_by_node(old_node);
		if (pdev == NULL) {
			pr_err("%s: Failed to find pdev to remove '%s'\n",
					__func__, old_node->full_name);
		} else {
			platform_device_unregister(pdev);
			platform_device_put(pdev);
		}
	}

	/* finally move the reference (if it exists) to the new node */
	if (old_node && new_node) {
		pdev = of_find_device_by_node(old_node);
		if (pdev != NULL) {
			pdev->dev.of_node = new_node;
			platform_device_put(pdev);
		}
	}
}

int of_overlay(int count, struct of_overlay_info *ovinfo_tab)
{
	struct of_overlay_info *ovinfo;
	int i, err;

	if (!ovinfo_tab)
		return -EINVAL;

	/* first we apply the overlays atomically */
	for (i = 0; i < count; i++) {

		ovinfo = &ovinfo_tab[i];

		ovinfo->old_target = __of_copy_tree(ovinfo->target, NULL,
				GFP_KERNEL);
		if (ovinfo->old_target == NULL) {
			pr_err("%s: Failed to copy tree '%s'\n",
					__func__, ovinfo->target->full_name);
			err = -ENOMEM;
			goto err_fail;
		}

		write_lock(&devtree_lock);
		err = __of_apply_tree_overlay(ovinfo->target, ovinfo->overlay,
				&allnodes);
		write_unlock(&devtree_lock);
		if (err != 0) {
			pr_err("%s: __of_apply_tree_overlay failed '%s'\n",
				__func__, ovinfo->target->full_name);
			goto err_fail;
		}
	}

	pr_info("%s: overlay done\n", __func__);

	/* note that devices might fail probing, we don't care */
	for (i = 0; i < count; i++) {
		ovinfo = &ovinfo_tab[i];
		of_apply_overlay_post(ovinfo->old_target, ovinfo->target);
	}

	pr_info("%s: done\n", __func__);

	return 0;

err_fail:
	while (--i >= 0) {
		ovinfo = &ovinfo_tab[i];

		__of_free_tree(ovinfo->old_target);
		/* FIXME: no overlay revert yet */
	}

	return err;
}

int of_fill_overlay_info(struct device_node *info_node,
		struct of_overlay_info *ovinfo)
{
	u32 val;
	int ret;

	if (!info_node || !ovinfo)
		return -EINVAL;

	/* clear */
	memset(ovinfo, 0, sizeof(*ovinfo));

	ret = of_property_read_u32(info_node, "target", &val);
	if (ret != 0)
		goto err_fail;

	ovinfo->target = of_find_node_by_phandle(val);
	if (ovinfo->target == NULL)
		goto err_fail;

	ovinfo->overlay = of_get_child_by_name(info_node, "__overlay__");
	if (ovinfo->overlay == NULL)
		goto err_fail;

	return 0;

err_fail:
	of_node_put(ovinfo->target);
	of_node_put(ovinfo->overlay);

	memset(ovinfo, 0, sizeof(*ovinfo));
	return -EINVAL;
}

int of_build_overlay_info(struct device_node *tree,
		int *cntp, struct of_overlay_info **ovinfop)
{
	struct device_node *node;
	struct of_overlay_info *ovinfo;
	int cnt, err;

	if (tree == NULL || cntp == NULL || ovinfop == NULL)
		return -EINVAL;

	/* worst case; every child is a node */
	cnt = 0;
	for_each_child_of_node(tree, node)
		cnt++;

	ovinfo = kzalloc(cnt * sizeof(*ovinfo), GFP_KERNEL);
	if (ovinfo == NULL)
		return -ENOMEM;

	cnt = 0;
	for_each_child_of_node(tree, node) {
		err = of_fill_overlay_info(node, &ovinfo[cnt]);
		if (err == 0) 
			cnt++;
	}

	/* if nothing filled, return error */
	if (cnt == 0) {
		kfree(ovinfo);
		return -ENODEV;
	}

	*cntp = cnt;
	*ovinfop = ovinfo;

	return 0;
}

int of_free_overlay_info(int count, struct of_overlay_info *ovinfo_tab)
{
	struct of_overlay_info *ovinfo;
	int i;

	if (!ovinfo_tab || count < 0)
		return -EINVAL;

	/* do it in reverse */
	for (i = count - 1; i >= 0; i--) {
		ovinfo = &ovinfo_tab[i];

		of_node_put(ovinfo->target);
		of_node_put(ovinfo->overlay);
		__of_free_tree(ovinfo->old_target);
	}
	kfree(ovinfo_tab);

	return 0;
}

