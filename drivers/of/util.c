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

/* copy a tree (in a dynamic|detached state) */ 
/* the tree is guaranteed to have allnext nodes starting from root */
struct device_node *__of_copy_tree(
		const struct device_node *src,
		struct device_node **allp,
		gfp_t flags)
{
	struct device_node *dst, *srcc, *dstc, **nodep;
	const struct property *prop;
	struct property *propn, **propp;
	struct device_node *tmp_allnodes;

	if (src == NULL)
		return NULL;

	dst = kzalloc(sizeof(*dst), flags);
	if (dst == NULL)
		return NULL;

	dst->name = kstrdup(src->name, flags);
	if (dst->name == NULL)
		goto err_return;

	dst->type = kstrdup(src->type, flags);
	if (dst->type == NULL)
		goto err_return;

	dst->full_name = kstrdup(src->full_name, flags);
	if (dst->type == NULL)
		goto err_return;

	dst->phandle = src->phandle;
	kref_init(&dst->kref);
	of_node_set_flag(dst, OF_DYNAMIC);

	/* no allp, first call */
	if (allp == NULL) {
		tmp_allnodes = NULL;
		allp = &tmp_allnodes;

		/* only the root node is marked as detached */ 
		of_node_set_flag(dst, OF_DETACHED);
	}

	/* copy properties */
	propp = &dst->properties;
	__for_each_property_of_node(src, prop) {

		propn = __of_copy_property(prop, flags);
		if (propn == NULL)
			goto err_return;
		*propp = propn;
		propp = &propn->next;
	}
	
	/* copy children */
	nodep = &dst->child;
	__for_each_child_of_node(src, srcc) {

		dstc = __of_copy_tree(srcc, allp, flags);
		if (dstc == NULL)
			goto err_return;

		/* point to parent */
		dstc->parent = dst;

		*nodep = dstc;
		nodep = &dstc->sibling;
	}

	/* add self to allp (last) */
	dst->allnext = *allp;
	*allp = dst;

	return dst;

err_return:
	__of_free_tree(dst);
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


#define OF_SEL_NA	0	/* not a selector node (Not Applicable) */
#define OF_SEL_NO_MATCH	1	/* selector node, but doesn't match */
#define OF_SEL_MATCH	2	/* selector node, with a match */

static int __of_node_version_selector(const struct device_node *node,
		void *selinfo, struct property **propp)
{
	const char *version = selinfo;	/* this is the version detected */
	struct property *prop;
	char *cp;
	int cplen, vlen, l;

	if (of_node_cmp(node->name, "__version__") != 0)
		return OF_SEL_NA;	/* not a selector node */

	/* don't use access functions that lock; do it manually */
	__for_each_property_of_node(node, prop) {
		if (of_prop_cmp(prop->name, "__version__") == 0)
			break;
	}

	/* it is a selector node, but with no property? */
	if (prop == NULL)
		return -EINVAL;

	cp = prop->value;
	cplen = prop->length;
	vlen = strlen(version);

	while (cplen > 0) {
		if (of_compat_cmp(cp, version, vlen) == 0) {
			*propp = prop;
			return OF_SEL_MATCH;
		}
		l = strlen(cp) + 1;
		cp += l;
		cplen -= l;
	}

	return OF_SEL_NO_MATCH;
}

/*
 * Copy a tree (in a dynamic|detached state) while applying selector
 * the tree is guaranteed to have allnext nodes starting from root
 * apply the selector to form the resulting tree
 *
 * Example __copy_of_tree_with_selector
 *
 * original                 | version = "2";  | version = "1";
 * -------------------------+-----------------+----------------
 * / {                      | / {             | / {
 *     foo = "bar";         |     foo = "bar";|     foo = "bar";
 *     __version__  {       |     baz;        | };
 *        __version__ = "2";| };              |
 *        baz;              |                 |
 *     };                   |                 |
 * };                       |                 |
 *
 * 
 */
struct device_node *__of_copy_tree_with_selector(
		const struct device_node *src,
		struct device_node **allp,
		int (*selector)(const struct device_node *node,
		       	void *sel_value, struct property **propp),
		void *sel_value,
		struct device_node *dst,	/* if not NULL, need to add */
		gfp_t flags)
{
	struct device_node *srcc, *dstc, **nodep;
	const struct property *prop;
	struct property *propn, **propp, *sel_prop;
	struct device_node *tmp_allnodes;
	int match;

	if (src == NULL)
		return NULL;

	/* match with selector */
	sel_prop = NULL;
	match = selector(src, sel_value, &sel_prop);

	/* selector node, but no match */
	if (match == OF_SEL_NO_MATCH)
		return ERR_PTR(-ENOENT);

	/* if normal node */
	if (match == OF_SEL_NA) {

		dst = kzalloc(sizeof(*dst), flags);
		if (dst == NULL)
			return NULL;

		dst->name = kstrdup(src->name, flags);
		if (dst->name == NULL)
			goto err_return;

		dst->type = kstrdup(src->type, flags);
		if (dst->type == NULL)
			goto err_return;

		dst->full_name = kstrdup(src->full_name, flags);
		if (dst->type == NULL)
			goto err_return;

		dst->phandle = src->phandle;
		kref_init(&dst->kref);
		of_node_set_flag(dst, OF_DYNAMIC);

		/* no allp, first call */
		if (allp == NULL) {
			tmp_allnodes = NULL;
			allp = &tmp_allnodes;

			/* only the root node is marked as detached */ 
			of_node_set_flag(dst, OF_DETACHED);
		}
	}

	/* copy properties */
	propp = &dst->properties;

	__for_each_property_of_node(src, prop) {

		/* always position at the end of the list */
		while ((*propp) != NULL)
			propp = &(*propp)->next;

		/* skip the selector property */
		if (sel_prop == prop)
			continue;

		propn = __of_copy_property(prop, flags);
		if (propn == NULL)
			goto err_return;
		*propp = propn;
		propp = &propn->next;
	}

	/* copy children (that match selector - or normal ones) */
	nodep = &dst->child;

	__for_each_child_of_node(src, srcc) {

		/* always position at the end of the list */
		while ((*nodep) != NULL)
			nodep = &(*nodep)->sibling;

		/* non-version child, recurse normally */
		dstc = __of_copy_tree_with_selector(srcc, allp,
				selector, sel_value, dst, flags);
		/* NULL means error */
		if (dstc == NULL)
			goto err_return;

		/* any other errors, are expected */
		if (IS_ERR(dstc))
			continue;

		/* point to parent */
		dstc->parent = dst;

		*nodep = dstc;
		nodep = &dstc->sibling;
	}

	/* if we matched then return -EAGAIN */
	if (match != OF_SEL_NA)
		return ERR_PTR(-EAGAIN);

	/* add self to allp */
	dst->allnext = *allp;
	allp = &dst->allnext;

	return dst;

err_return:
	__of_free_tree(dst);
	return NULL;
}

struct device_node *__of_copy_tree_with_version_selector(
		const struct device_node *src,
		struct device_node **allp,
		char *version,
		gfp_t flags)
{
	return __of_copy_tree_with_selector(src, allp,
			__of_node_version_selector, version, NULL, flags);
}

/* remove a node and it's children from allnodes */
int __of_remove_from_allnodes(struct device_node *node,
		struct device_node **allnodesp,
		struct device_node **new_allnodesp)
{
	struct device_node *child;
	struct device_node **npp;
	int ret;

	/* children get removed first */
	__for_each_child_of_node(node, child) {
		ret = __of_remove_from_allnodes(child,
				allnodesp, new_allnodesp);
		if (ret != 0)
			return ret;
	}

	/* find on allnodesp */
	npp = allnodesp;
	while ((*npp) != NULL) {
		if ((*npp) == node)
			break;
		npp = &(*npp)->allnext;
	}
	if (*npp == NULL)	/* pretty bad */
		return -ENOENT;

	/* remove from allnodep */
	*npp = (*npp)->allnext;

	/* add to new_allnodesp */
	node->allnext = *new_allnodesp;
	*new_allnodesp = node;

	/* guaranteed that the root of the tree is the head */
	return 0;
}

struct property *__of_find_property(const struct device_node *np,
				  const char *name,
				  int *lenp)
{
	struct property *pp;

	if (!np)
		return NULL;

	__for_each_property_of_node(np, pp) {
		if (of_prop_cmp(pp->name, name) == 0) {
			if (lenp)
				*lenp = pp->length;
			break;
		}
	}

	return pp;
}

const void *__of_get_property(const struct device_node *np, const char *name,
			 int *lenp)
{
	struct property *pp = __of_find_property(np, name, lenp);

	return pp ? pp->value : NULL;
}

int __of_device_is_available(const struct device_node *device)
{
	const char *status;
	int statlen;

	status = __of_get_property(device, "status", &statlen);
	if (status == NULL)
		return 1;

	if (statlen > 0) {
		if (!strcmp(status, "okay") || !strcmp(status, "ok"))
			return 1;
	}

	return 0;
}

#define OF_MARK_PARENT		29
#define OF_MARK_ALLNODES	30
#define OF_MARK_CHILD		31

int __of_allnodes_count(struct device_node *all_nodes)
{
	struct device_node *node;
	int count;

	count = 0;
	for (node = all_nodes; node != NULL; node = node->allnext) {

		if (of_node_check_flag(node, OF_MARK_ALLNODES)) {
			pr_err("%s: node %p (%s) encountered twice!\n", __func__,
					node, node->full_name);
			pr_err("%s: #%d so far\n", __func__, count);
			return -EINVAL;
		}

		of_node_set_flag(node, OF_MARK_ALLNODES);
		count++;
	}

	return count;
}

void __of_clear_allnodes_marks(struct device_node *all_nodes)
{
	struct device_node *node;

	for (node = all_nodes; node != NULL; node = node->allnext)
		of_node_clear_flag(node, OF_MARK_ALLNODES);
}

int __of_tree_count_children(struct device_node *node)
{
	struct device_node *child;
	int count, ret;

	/* check if we encountered this node before */
	if (of_node_check_flag(node, OF_MARK_CHILD)) {
		pr_err("%s: node %p (%s) encountered twice!\n", __func__,
				node, node->full_name);
		return -EINVAL;
	}

	of_node_set_flag(node, OF_MARK_CHILD);
	count = 1;

	__for_each_child_of_node(node, child) {
		ret = __of_tree_count_children(child);
		if (ret <= 0)
			return ret;
		count += ret;
	}

	return count;
}

void __of_tree_clear_child_marks(struct device_node *node)
{
	struct device_node *child;

	of_node_clear_flag(node, OF_MARK_CHILD);

	__for_each_child_of_node(node, child)
		__of_tree_clear_child_marks(child);
}

int __of_tree_verify_parent(struct device_node *tree,
		struct device_node *all_nodes)
{
	struct device_node *node, *node2;

	/* verify that this is a root */
	if (tree->parent != NULL) {
		pr_err("%s: tree not root!\n", __func__);
		return -EINVAL;
	}

	for (node = all_nodes; node != NULL; node = node->allnext) {

		node2 = node;
		while (node2 != tree) {

			if (node2->parent == NULL) {
				pr_err("%s: node %p (%s) broken parent\n",
					__func__, node2, node2->full_name);
				return -EINVAL;
			}
			if (of_node_check_flag(node2, OF_MARK_PARENT)) {
				pr_err("%s: node %p (%s) traverse twice\n",
					__func__, node2, node2->full_name);
				return -EINVAL;
			}
			of_node_set_flag(node2, OF_MARK_PARENT);

			node2 = node2->parent;
		}

		/* All OK, remove marks */
		node2 = node;
		while (node2 != tree) {
			of_node_clear_flag(node2, OF_MARK_PARENT);
			node2 = node2->parent;
		}
	}

	return 0;
}

void __of_clear_parent_marks(struct device_node *all_nodes)
{
	struct device_node *node;

	for (node = all_nodes; node != NULL; node = node->allnext)
		of_node_clear_flag(node, OF_MARK_PARENT);
}

void __of_tree_verify(struct device_node *tree, struct device_node *all_nodes)
{
	int all_nodes_count, child_nodes_count, ret;

	child_nodes_count = __of_tree_count_children(tree);
	all_nodes_count = __of_allnodes_count(all_nodes);

	if (child_nodes_count != all_nodes_count) {
		pr_info("%s: all_nodes_count=%d, child_nodes_count=%d\n", __func__,
				all_nodes_count, child_nodes_count);
		WARN_ON(child_nodes_count != all_nodes_count);

	} else {
		ret = __of_tree_verify_parent(tree, all_nodes);
		WARN_ON(ret != 0);
		__of_tree_clear_child_marks(tree);
	}
	__of_clear_allnodes_marks(all_nodes);
	__of_clear_parent_marks(all_nodes);
}

void of_tree_verify(struct device_node *tree, struct device_node *all_nodes)
{
	write_lock(&devtree_lock);
	__of_tree_verify(tree, all_nodes);
	write_unlock(&devtree_lock);
}	
