/*
 * Functions for dumping device trees
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

/*******************************************************************/

int of_is_printable_string(const void *data, int len)
{
	const char *s = data;
	const char *ss, *se;

	/* zero length is not */
	if (len == 0)
		return 0;

	/* must terminate with zero */
	if (s[len - 1] != '\0')
		return 0;

	se = s + len;

	while (s < se) {
		ss = s;
		while (s < se && *s && isprint(*s))
			s++;

		/* not zero, or not done yet */
		if (*s != '\0' || s == ss)
			return 0;

		s++;
	}

	return 1;
}

char *__of_dump_prop(struct property *prop)
{
	const void *data = prop->value;
	int len = prop->length;
	int i, tbuflen;
	const char *p = data;
	const char *s;
	char *buf, *bufp, *bufe;

	/* play it safe */
	buf = kmalloc(PAGE_SIZE + len * 8, GFP_KERNEL);
	if (buf == NULL)
		return NULL;
	bufp = buf;
	bufe = buf + PAGE_SIZE + len * 8;

#undef append_sprintf
#define append_sprintf(format, ...) \
	do { \
		tbuflen = snprintf(NULL, 0, format, ## __VA_ARGS__); \
		if (bufp + tbuflen + 1 >= bufe) \
			goto err_out; \
		snprintf(bufp, tbuflen + 1, format, ## __VA_ARGS__); \
		bufp += tbuflen; \
	} while(0)

	if (len == 0) {
		/* nothing; just terminate */
		*buf = '\0';
		return buf;
	}

	append_sprintf(" = ");

	if (of_is_printable_string(data, len)) {
		s = data;
		do {
			append_sprintf("\"%s\"", s);
			s += strlen(s) + 1;
			if (s < (const char *)data + len)
				append_sprintf(", ");
		} while (s < (const char *)data + len);

	} else if ((len % 4) == 0) {
		append_sprintf("<");
		for (i = 0; i < len; i += 4)
			append_sprintf("0x%08x%s",
				be32_to_cpu(*(uint32_t *)(p + i)),
				i < (len - 4) ? " " : "");
		append_sprintf(">");
	} else {
		append_sprintf("[");
		for (i = 0; i < len; i++)
			append_sprintf("%02x%s", *(p + i),
					i < len - 1 ? " " : "");
		append_sprintf("]");
	}

	return buf;
err_out:
	kfree(buf);
	return NULL;
#undef append_sprintf
}

static const char leveltab[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";
static const int maxlevel = sizeof(leveltab);

void __of_dev_dump_tree(struct device *dev, int level,
		struct device_node *node)
{
	struct device_node *child;
	struct property *prop;
	const char *thislevel;
	const char *nextlevel;
	char *propstr;

	thislevel = leveltab + maxlevel - level;
	if (thislevel < leveltab)
		thislevel = leveltab;
	nextlevel = thislevel - 1;
	if (nextlevel < leveltab)
		nextlevel = leveltab;

	dev_info(dev, "%s%s { # %s %d\n", thislevel, node->name,
			node->full_name, atomic_read(&node->kref.refcount));

	for_each_property_of_node(node, prop) {

		if (strcmp(prop->name, "name") == 0)
			continue;

		propstr = __of_dump_prop(prop);
		dev_info(dev, "%s%s%s;\n", nextlevel, prop->name,
				propstr ? propstr : "*ERROR*");
		kfree(propstr);
	}

	for_each_child_of_node(node, child)
		__of_dev_dump_tree(dev, level + 1, child);

	dev_info(dev, "%s};", thislevel);
}

void of_dev_dump_tree(struct device *dev, struct device_node *node)
{
	__of_dev_dump_tree(dev, 1, node);
}

void __of_dump_tree(int level,
		struct device_node *node)
{
	struct device_node *child;
	struct property *prop;
	const char *thislevel;
	const char *nextlevel;
	char *propstr;

	thislevel = leveltab + maxlevel - level;
	if (thislevel < leveltab)
		thislevel = leveltab;
	nextlevel = thislevel - 1;
	if (nextlevel < leveltab)
		nextlevel = leveltab;

	pr_info("%s%s { # %s %d\n", thislevel, node->name,
			node->full_name, atomic_read(&node->kref.refcount));

	for_each_property_of_node(node, prop) {

		if (strcmp(prop->name, "name") == 0)
			continue;

		propstr = __of_dump_prop(prop);
		pr_info("%s%s%s;\n", nextlevel, prop->name,
				propstr ? propstr : "*ERROR*");
		kfree(propstr);
	}

	for_each_child_of_node(node, child)
		__of_dump_tree(level + 1, child);

	pr_info("%s};\n", thislevel);
}

void of_dump_tree(struct device_node *node)
{
	__of_dump_tree(1, node);
}
