/*
 * PRU driver for TI's AM33xx series of SoCs
 *
 * Copyright (C) 2013 Pantelis Antoniou <panto@antoniou-consulting.com>
 *
 * This file is licensed under the terms of the GNU General Public License
 * version 2.  This program is licensed "as is" without any warranty of any
 * kind, whether express or implied.
 */

#define DEBUG

#include <linux/module.h>
#include <linux/err.h>
#include <linux/dma-mapping.h>
#include <linux/remoteproc.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/genalloc.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/pm_runtime.h>
#include <linux/pinctrl/consumer.h>
#include <linux/io.h>
#include <plat/mailbox.h>
#include <linux/virtio_ids.h>
#include <linux/elf.h>
#include <linux/byteorder/generic.h>

#include "remoteproc_internal.h"

#define MAX_PRU_INTS	8

/* PRU control structure */
struct pruproc {
	struct rproc *rproc;
	struct platform_device *pdev;
	struct resource_table *table;
	int table_size;
	void __iomem *vaddr;
	dma_addr_t paddr;
	struct omap_mbox *mbox;
	struct notifier_block nb;
	unsigned int pintc_offset;
	unsigned int pctrl_offset[2];
	int num_irqs;
	int irqs[MAX_PRU_INTS];
	int events[MAX_PRU_INTS];
	const char *fw_name;
	unsigned int is_elf : 1;
};

/* global memory map (for am33xx) (almost the same as local) */
#define PRU_DATA_RAM0		0x00000
#define PRU_DATA_RAM1		0x02000
#define PRU_SHARED_DATA_RAM	0x10000
#define PRU_INTC		0x20000
#define PRU_PRU0_CONTROL	0x22000
#define PRU_PRU0_DEBUG		0x22400
#define PRU_PRU1_CONTROL	0x24000
#define PRU_PRU1_DEBUG		0x24400
#define PRU_CFG			0x26000
#define PRU_UART0		0x28000
#define PRU_IEP			0x2E000
#define PRU_ECAP0		0x30000
#define PRU_MII_RT_CFG		0x32000
#define PRU_MII_MDIO		0x32400
#define PRU_INSN_RAM0		0x34000
#define PRU_INSN_RAM1		0x38000

/* PRU CONTROL */
#define PCTRL_CONTROL		0x0000
#define  CONTROL_SOFT_RST_N	0x0001
#define  CONTROL_ENABLE		0x0002
#define  CONTROL_SLEEPING	0x0004
#define  CONTROL_COUNTER_ENABLE	0x0008

#define PCTRL_STATUS		0x0004
#define PCTRL_WAKEUP_EN		0x0008
#define PCTRL_CYCLE		0x000C
#define PCTRL_STALL		0x0010
#define PCTRL_CTBIR0		0x0020
#define PCTRL_CTBIR1		0x0024
#define PCTRL_CTPPR0		0x0028
#define PCTRL_CTPPR1		0x002C

/* PRU INTC */
#define PINTC_REVID		0x0000
#define PINTC_CR		0x0004
#define PINTC_GER		0x0010
#define PINTC_GNLR		0x001C
#define PINTC_SISR		0x0020
#define PINTC_SICR		0x0024
#define PINTC_EISR		0x0028
#define PINTC_EICR		0x002C
#define PINTC_HIEISR		0x0034
#define PINTC_HIDISR		0x0038
#define PINTC_GPIR		0x0080
#define PINTC_SRSR0		0x0200
#define PINTC_SRSR1		0x0204
#define PINTC_SECR0		0x0280
#define PINTC_SECR1		0x0284
#define PINTC_ESR0		0x0300
#define PINTC_ESR1		0x0304
#define PINTC_ECR0		0x0380
#define PINTC_ECR1		0x0384
#define PINTC_CMR0		0x0400
#define PINTC_CMR1		0x0404
#define PINTC_CMR2		0x0408
#define PINTC_CMR3		0x040C
#define PINTC_CMR4		0x0410
#define PINTC_CMR5		0x0414
#define PINTC_CMR6		0x0418
#define PINTC_CMR7		0x041C
#define PINTC_CMR8		0x0420
#define PINTC_CMR9		0x0424
#define PINTC_CMR10		0x0428
#define PINTC_CMR11		0x042C
#define PINTC_CMR12		0x0430
#define PINTC_CMR13		0x0434
#define PINTC_CMR14		0x0438
#define PINTC_CMR15		0x043C
#define PINTC_HMR0		0x0800
#define PINTC_HMR1		0x0804
#define PINTC_HMR2		0x0808
#define PINTC_HIPIR0		0x0900
#define PINTC_HIPIR1		0x0904
#define PINTC_HIPIR2		0x0908
#define PINTC_HIPIR3		0x090C
#define PINTC_HIPIR4		0x0910
#define PINTC_HIPIR5		0x0914
#define PINTC_HIPIR6		0x0918
#define PINTC_HIPIR7		0x091C
#define PINTC_HIPIR8		0x0920
#define PINTC_HIPIR9		0x0924
#define PINTC_SIPR0		0x0D00
#define PINTC_SIPR1		0x0D04
#define PINTC_SITR0		0x0D80
#define PINTC_SITR1		0x0D84
#define PINTC_HINLR0		0x1100
#define PINTC_HINLR1		0x1104
#define PINTC_HINLR2		0x1108
#define PINTC_HINLR3		0x110C
#define PINTC_HINLR4		0x1110
#define PINTC_HINLR5		0x1114
#define PINTC_HINLR6		0x1118
#define PINTC_HINLR7		0x111C
#define PINTC_HINLR8		0x1120
#define PINTC_HINLR9		0x1124
#define PINTC_HIER		0x1500

#define HIPIR_NOPEND		0x80000000

static inline u32 pru_read_reg(struct pruproc *pp, unsigned int reg)
{
	return __raw_readl(pp->vaddr + reg);
}

static inline void pru_write_reg(struct pruproc *pp, unsigned int reg,
		u32 val)
{
	__raw_writel(val, pp->vaddr + reg);
}

static inline u32 pintc_read_reg(struct pruproc *pp, unsigned int reg)
{
	return pru_read_reg(pp, reg + pp->pintc_offset);
}

static inline void pintc_write_reg(struct pruproc *pp, unsigned int reg,
		u32 val)
{
	return pru_write_reg(pp, reg + pp->pintc_offset, val);
}

static inline u32 pcntrl_read_reg(struct pruproc *pp, int pru, unsigned int reg)
{
	if ((unsigned int)pru >= 2)
		return (u32)-1;
	return pru_read_reg(pp, reg + pp->pctrl_offset[pru]);
}

static inline void pcntrl_write_reg(struct pruproc *pp, int pru, unsigned int reg,
		u32 val)
{
	if ((unsigned int)pru >= 2)
		return;
	return pru_write_reg(pp, reg + pp->pctrl_offset[pru], val);
}

static int pruproc_bin_sanity_check(struct rproc *rproc, const struct firmware *fw)
{
	return 0;
}

/* Loads the firmware to shared memory. */
static int pruproc_bin_load_segments(struct rproc *rproc, const struct firmware *fw)
{
	struct pruproc *pp = rproc->priv;
	unsigned int offset = PRU_INSN_RAM0;
	void __iomem *va = pp->vaddr + offset;

	pcntrl_write_reg(pp, 0, PCTRL_CONTROL, CONTROL_SOFT_RST_N);

	/* just copy */
	memcpy(va, fw->data, fw->size);

	return 0;
}

static int
pruproc_elf_sanity_check(struct rproc *rproc, const struct firmware *fw)
{
	const char *name = rproc->firmware;
	struct device *dev = &rproc->dev;
	struct elf32_hdr *ehdr;
	char class;

	if (!fw) {
		dev_err(dev, "failed to load %s\n", name);
		return -EINVAL;
	}

	if (fw->size < sizeof(struct elf32_hdr)) {
		dev_err(dev, "Image is too small\n");
		return -EINVAL;
	}

	ehdr = (struct elf32_hdr *)fw->data;

	/* We only support ELF32 at this point */
	class = ehdr->e_ident[EI_CLASS];
	if (class != ELFCLASS32) {
		dev_err(dev, "Unsupported class: %d\n", class);
		return -EINVAL;
	}

	/* PRU is little endian */
	if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
		dev_err(dev, "Unsupported firmware endianness\n");
		return -EINVAL;
	}

	if (fw->size < le32_to_cpu(ehdr->e_shoff) +
			sizeof(struct elf32_shdr)) {
		dev_err(dev, "Image is too small\n");
		return -EINVAL;
	}

	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
		dev_err(dev, "Image is corrupted (bad magic)\n");
		return -EINVAL;
	}

	if (le16_to_cpu(ehdr->e_phnum) == 0) {
		dev_err(dev, "No loadable segments\n");
		return -EINVAL;
	}

	if (le32_to_cpu(ehdr->e_phoff) > fw->size) {
		dev_err(dev, "Firmware size is too small\n");
		return -EINVAL;
	}

	return 0;
}

static int
pruproc_elf_load_segments(struct rproc *rproc, const struct firmware *fw)
{
	struct device *dev = &rproc->dev;
	struct pruproc *pp = rproc->priv;
	struct elf32_hdr *ehdr;
	struct elf32_phdr *phdr;
	int i, ret = 0;
	const u8 *elf_data = fw->data;
	u32 da, memsz, filesz, offset, flags;
	u32 sect_offset, sect_maxsz;
	void *ptr;

	ehdr = (struct elf32_hdr *)elf_data;
	phdr = (struct elf32_phdr *)(elf_data + le32_to_cpu(ehdr->e_phoff));

	/* go through the available ELF segments */
	for (i = 0; i < le16_to_cpu(ehdr->e_phnum); i++, phdr++) {

		da = le32_to_cpu(phdr->p_paddr);
		memsz = le32_to_cpu(phdr->p_memsz);
		filesz = le32_to_cpu(phdr->p_filesz);
		offset = le32_to_cpu(phdr->p_offset);
		flags = le32_to_cpu(phdr->p_flags);

		if (le32_to_cpu(phdr->p_type) != PT_LOAD)
			continue;

		dev_dbg(dev, "phdr: type %d da 0x%x memsz 0x%x filesz 0x%x"
				    " flags %c%c%c\n",
					le32_to_cpu(phdr->p_type),
					da, memsz, filesz,
					(flags & PF_R) ? 'R' : '-',
					(flags & PF_W) ? 'W' : '-',
					(flags & PF_X) ? 'W' : '-');

		/* PRU is not a unified address space architecture */
		/* we need to map differently executable & data segments */

		if (filesz > memsz) {
			dev_err(dev, "bad phdr filesz 0x%x memsz 0x%x\n",
							filesz, memsz);
			ret = -EINVAL;
			break;
		}

		if (offset + filesz > fw->size) {
			dev_err(dev, "truncated fw: need 0x%x avail 0x%zx\n",
					offset + filesz, fw->size);
			ret = -EINVAL;
			break;
		}

		/* we can't use rproc_da_to_va */

		/* text? to code area */
		if (flags & PF_X) {
			sect_offset = PRU_INSN_RAM0;
			sect_maxsz = 0x2000;
		} else {
			sect_offset = PRU_DATA_RAM0;
			sect_maxsz = 0x2000;
		}

		/* TODO: check for spill over */

		ptr = pp->vaddr + sect_offset + offset;

		/* put the segment where the remote processor expects it */
		if (filesz > 0)
			memcpy(ptr, elf_data + offset, filesz);
		else
			memset(ptr, 0, memsz);
	}

	return ret;
}

static
u32 pruproc_elf_get_boot_addr(struct rproc *rproc, const struct firmware *fw)
{
	struct elf32_hdr *ehdr  = (struct elf32_hdr *)fw->data;

	return le32_to_cpu(ehdr->e_entry);
}

/* just return the built-firmware resources */
static struct resource_table *
pruproc_find_rsc_table(struct rproc *rproc, const struct firmware *fw,
		     int *tablesz)
{
	struct pruproc *pp = rproc->priv;

	*tablesz = pp->table_size;
	return pp->table;
}

/* PRU binary firmware handler operations */
const struct rproc_fw_ops pruproc_bin_fw_ops = {
	.find_rsc_table	= pruproc_find_rsc_table,
	.load		= pruproc_bin_load_segments,
	.sanity_check	= pruproc_bin_sanity_check,
};

/* PRU elf handler operations */
const struct rproc_fw_ops pruproc_elf_fw_ops = {
	.find_rsc_table	= pruproc_find_rsc_table,
	.load		= pruproc_elf_load_segments,
	.sanity_check	= pruproc_elf_sanity_check,
	.get_boot_addr	= pruproc_elf_get_boot_addr,
};

/* Kick the modem with specified notification id */
static void pruproc_kick(struct rproc *rproc, int vqid)
{
	struct pruproc *pp = rproc->priv;
	struct device *dev = &pp->pdev->dev;

	dev_dbg(dev, "kick vqid:%d\n", vqid);
}

/* Start the PRU modem */
static int pruproc_start(struct rproc *rproc)
{
	struct pruproc *pp = rproc->priv;
	struct device *dev = &pp->pdev->dev;

	dev_dbg(dev, "start pru\n");

	pcntrl_write_reg(pp, 0, PCTRL_CONTROL, CONTROL_ENABLE);

	dev_dbg(dev, "PCTRL_CONTROL=0x%08x\n",
			pcntrl_read_reg(pp, 0, PCTRL_CONTROL));

	dev_dbg(dev, "PCTRL_STATUS=0x%08x\n",
			pcntrl_read_reg(pp, 0, PCTRL_STATUS));

	return 0;
}

/* Stop the PRU modem */
static int pruproc_stop(struct rproc *rproc)
{
	struct pruproc *pp = rproc->priv;
	struct device *dev = &pp->pdev->dev;

	dev_dbg(dev, "stop PRU\n");

	return 0;
}

static void *pruproc_alloc_vring(struct rproc *rproc,
		const struct fw_rsc_vdev_vring *vring,
		int size, dma_addr_t *dma)
{
	struct pruproc *pp = rproc->priv;
	struct device *dev = &pp->pdev->dev;
	void *va;

	if (vring->da < PRU_SHARED_DATA_RAM ||
			vring->da >= PRU_SHARED_DATA_RAM + 0x3000) {
		dev_err(dev, "DA outside of shared DATA RAM\n");
		return NULL;
	}

	/* simple mapping (global=local) offset */
	va = pp->vaddr + vring->da;
	*dma = pp->paddr + vring->da;

	dev_dbg(dev, "%s: da=0x%x, va=%p, dma=0x%llx\n", __func__,
			vring->da, va, (unsigned long long)*dma);
	return va;
}

static void pruproc_free_vring(struct rproc *rproc,
		const struct fw_rsc_vdev_vring *vring,
		int size, void *va, dma_addr_t dma)
{
	/* nothing to do */
}

static struct rproc_ops pruproc_ops = {
	.start		= pruproc_start,
	.stop		= pruproc_stop,
	.kick		= pruproc_kick,

	.alloc_vring	= pruproc_alloc_vring,
	.free_vring	= pruproc_free_vring,
};

/* PRU is unregistered */
static int pruproc_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pruproc *pp = platform_get_drvdata(pdev);

	dev_dbg(dev, "remove pru\n");

	/* Unregister as remoteproc device */
	rproc_del(pp->rproc);
	rproc_put(pp->rproc);

	platform_set_drvdata(pdev, NULL);

	return 0;
}

static irqreturn_t pru_handler(int irq, void *data)
{
	struct pruproc *pp = data;
	struct device *dev = &pp->pdev->dev;
	int i, ev;
	u32 val;

	/* find out which IRQ we got */
	for (i = 0; i < pp->num_irqs; i++)
		if (irq == pp->irqs[i])
			break;
	if (i >= pp->num_irqs)
		return IRQ_NONE;

	ev = pp->events[i];

	val = pintc_read_reg(pp, PINTC_HIER);

	/* check bit of interrupt */
	if ((val & (1 << ev)) == 0)
		return IRQ_NONE;

	/* check non-pending bit of specific event */
	val = pintc_read_reg(pp, PINTC_HIPIR0 + (ev << 2));
	if ((val & HIPIR_NOPEND) != 0)
		return IRQ_NONE;

	/* disable the interrupt */
	dev_info(dev, "Got interrupt #%d, event %d\n", irq, ev);

	pintc_write_reg(pp, PINTC_HIDISR, (1 << ev));

	return IRQ_HANDLED;
}

struct pru_resource_table {
	struct resource_table	rsc;

	/* offsets */
	u32	offset[1];

	/* fw_rsc_vdev */
	struct fw_rsc_hdr		vdev_hdr;
	struct fw_rsc_vdev		vdev;
	struct fw_rsc_vdev_vring	vdev_ring[2];

} __packed;

static int build_rsc_table(struct platform_device *pdev, struct pruproc *pp)
{
	struct device *dev = &pdev->dev;
	struct device_node *node = dev->of_node;
	struct device_node *rnode = NULL;	/* resource table node */
	struct device_node *rvnode = NULL;	/* vdev node */
	struct resource_table *rsc;
	struct fw_rsc_hdr *rsc_hdr;
	struct fw_rsc_vdev *rsc_vdev;
	char vring_name[16];
	u32 vring_data[4], val;
	struct fw_rsc_vdev_vring *rsc_vring;
	void *table, *p;
	int i, err, table_size, num_vrings;

	if (node == NULL) {
		dev_err(dev, "No OF device node\n");
		return -EINVAL;
	}

	/* verify OF data */

	/* first find a valid resource-table node */
	for_each_child_of_node(node, rnode) {
		if (of_property_read_bool(rnode, "resource-table"))
			break;
	}

	/* no resource node found */
	if (rnode == NULL) {
		dev_err(dev, "No resource-table node node\n");
		return -EINVAL;
	}

	/* now find out the vdev node */
	for_each_child_of_node(rnode, rvnode) {
		if (of_property_read_bool(rvnode, "vdev"))
			break;
	}

	table_size = sizeof(struct resource_table);

	num_vrings = 0;
	if (rvnode != NULL) {
		/* hardcoded limit is 256 vrings */
		for (num_vrings = 0; num_vrings < 256; num_vrings++) {
			snprintf(vring_name, sizeof(vring_name), "vring-%d",
					num_vrings);
			if (of_property_read_u32_array(rvnode, vring_name,
					vring_data, ARRAY_SIZE(vring_data)) != 0)
				break;
		}

		table_size += sizeof(u32) +
		     sizeof(struct fw_rsc_hdr) +
		     sizeof(struct fw_rsc_vdev) +
		     sizeof(struct fw_rsc_vdev_vring) * num_vrings;
	}

	table = devm_kzalloc(dev, table_size, GFP_KERNEL);
	if (table == NULL) {
		dev_err(dev, "Failed to allocate resource table\n");
		err = -ENOMEM;
		goto err_fail;
	}
	pp->table = table;
	pp->table_size = table_size;

	p = table;	/* pointer at start */

	/* resource table */
	rsc = p;
	p += sizeof(*rsc);
	rsc->ver = 1;	/* resource table version 1 */
	if (rvnode != NULL)
		rsc->num = 1;	/* only support vdev for now */
	else
		rsc->num = 0;

	/* offsets */
	p += rsc->num * sizeof(u32);	/* point after offsets */
	if (rsc->num > 0) {

		rsc_hdr = p;
		rsc->offset[0] = p - table;

		/* resource header */
		p += sizeof(*rsc_hdr);
		rsc_hdr->type = RSC_VDEV;

		/* vdev */
		rsc_vdev = p;
		p += sizeof(*rsc_vdev);
		/* rpmsg for now */
		rsc_vdev->id = VIRTIO_ID_RPMSG;
		err = of_property_read_u32(rvnode, "notifyid", &val);
		if (err != 0) {
			dev_err(dev, "no notifyid vdev property\n");
			goto err_fail;
		}
		rsc_vdev->notifyid = val;
		rsc_vdev->dfeatures = 0;
		rsc_vdev->gfeatures = 0;
		rsc_vdev->config_len = 0;
		rsc_vdev->status = 0;
		rsc_vdev->num_of_vrings = num_vrings;

		for (i = 0; i < num_vrings; i++) {
			rsc_vring = p;
			p += sizeof(*rsc_vring);

			snprintf(vring_name, sizeof(vring_name), "vring-%d",
					i);
			err = of_property_read_u32_array(rvnode, vring_name,
					vring_data, ARRAY_SIZE(vring_data));
			if (err != 0) {
				dev_err(dev, "no %s property\n", vring_name);
				goto err_fail;
			}
			rsc_vring->da = vring_data[0];
			rsc_vring->align = vring_data[1];
			rsc_vring->num = vring_data[2];
			rsc_vring->notifyid = vring_data[3];
		}
	}

	err = 0;

err_fail:
	of_node_put(rvnode);	/* of_node_put(NULL) is a NOP */
	of_node_put(rnode);

	return err;
}

/* Handle probe of a modem device */
static int pruproc_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pruproc *pp;
	const char *fw_name;
	int pm_get = 0;
	struct rproc *rproc = NULL;
	struct resource *res;
	struct pinctrl *pinctrl;
	u32 val;
	int err, i, irq;

	/* get pinctrl */
	pinctrl = devm_pinctrl_get_select_default(dev);
	if (IS_ERR(pinctrl)) {
		err = PTR_ERR(pinctrl);
		/* deferring probe */
		if (err == -EPROBE_DEFER) {
			dev_warn(dev, "deferring proble\n");
			return err;
		}
		dev_warn(dev, "pins are not configured from the driver\n");
	}

	/* we only work on OF */
	if (dev->of_node == NULL) {
		dev_err(dev, "Only OF configuration supported\n");
		err = -ENODEV;
		goto err_fail;
	}

	pm_runtime_enable(dev);
	err = pm_runtime_get_sync(dev);
	if (err != 0) {
		dev_err(dev, "pm_runtime_get_sync failed\n");
		goto err_fail;
	}
	pm_get = 1;

	err = dma_set_coherent_mask(dev, DMA_BIT_MASK(32));
	if (err) {
		dev_err(dev, "dma_set_coherent_mask: %d\n", err);
		goto err_fail;
	}

	err = of_property_read_string(dev->of_node, "ti,firmware", &fw_name);
	if (err != 0) {
		dev_err(dev, "can't find fw property %s\n", "ti,firmware");
		goto err_fail;
	}
	rproc = rproc_alloc(dev, pdev->name, &pruproc_ops, fw_name,
			sizeof(*pp));
	if (!rproc) {
		dev_err(dev, "rproc_alloc failed\n");
		err = -ENOMEM;
		goto err_fail;
	}

	pp = rproc->priv;
	pp->pdev = pdev;
	pp->rproc = rproc;
	pp->fw_name = fw_name;

	/* zero the irqs */
	for (i = 0; i < ARRAY_SIZE(pp->irqs); i++)
		pp->irqs[i] = -1;

	for (i = 0; i < ARRAY_SIZE(pp->events); i++)
		pp->events[i] = -1;

	err = of_property_read_u32(dev->of_node, "ti,pintc-offset", &val);
	if (err != 0) {
		dev_err(dev, "no ti,pintc-offset property\n");
		goto err_fail;
	}
	pp->pintc_offset = val;

	/* check firmware type */
	pp->is_elf = of_property_read_bool(dev->of_node, "ti,elf");

	pp->pctrl_offset[0] = PRU_PRU0_CONTROL;
	pp->pctrl_offset[1] = PRU_PRU1_CONTROL;

	for (i = 0; i < ARRAY_SIZE(pp->irqs); i++) {

		err = platform_get_irq(pdev, i);
		if (err < 0)
			break;
		irq = err;

		pp->irqs[i] = irq;

		err = devm_request_irq(dev, irq, pru_handler, 0,
				dev_name(dev), pp);
		if (err != 0) {
			dev_err(dev, "Failed to register irq %d\n", irq);
			goto err_fail;
		}
	}
	pp->num_irqs = i;

	err = of_property_read_u32_array(dev->of_node, "events",
			pp->events, pp->num_irqs);
	if (err != 0) {
		dev_err(dev, "Failed to read events array\n");
		goto err_fail;
	}

	dev_info(dev, "#%d PRU interrupts registered\n", pp->num_irqs);

	platform_set_drvdata(pdev, pp);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (res == NULL) {
		dev_err(dev, "failed to parse MEM resource\n");
		goto err_fail;
	}

	pp->paddr = res->start;
	pp->vaddr = devm_ioremap(dev, res->start, resource_size(res));
	if (pp->vaddr == NULL) {
		dev_err(dev, "failed to parse MEM resource\n");
		goto err_fail;
	}

	/* build the resource table from DT */
	err = build_rsc_table(pdev, pp);
	if (err != 0) {
		dev_err(dev, "failed to build resource table\n");
		goto err_fail;
	}

	/* Set the PRU specific firmware handler */
	if (!pp->is_elf)
		rproc->fw_ops = &pruproc_bin_fw_ops;
	else
		rproc->fw_ops = &pruproc_elf_fw_ops;

	/* Register as a remoteproc device */
	err = rproc_add(rproc);
	if (err) {
		dev_err(dev, "rproc_add failed\n");
		goto err_fail;
	}

	dev_info(dev, "Loaded OK\n");

	return 0;
err_fail:
	if (rproc)
		rproc_put(rproc);
	if (pm_get)
		pm_runtime_disable(dev);
	return err;
}

static const struct of_device_id pru_rproc_dt_ids[] = {
	{ .compatible = "ti,pru-rproc", .data = NULL, },
	{},
};
MODULE_DEVICE_TABLE(of, pruss_dt_ids);

static struct platform_driver pruproc_driver = {
	.driver	= {
		.name	= "pru-rproc",
		.owner	= THIS_MODULE,
		.of_match_table = pru_rproc_dt_ids,
	},
	.probe	= pruproc_probe,
	.remove	= pruproc_remove,
};

module_platform_driver(pruproc_driver);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("PRU Remote Processor control driver");
MODULE_AUTHOR("Pantelis Antoniou <panto@antoniou-consulting.com>");
