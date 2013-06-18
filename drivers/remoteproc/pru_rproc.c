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

/* PRU_EVTOUT0 is halt (system call) */

#define MAX_ARM_PRU_INTS	8
#define MAX_PRU_SYS_EVENTS	64
#define MAX_PRU_CHANNELS	10
#define MAX_PRU_HOST_INT	10

struct pruproc;

/* per PRU core control structure */
struct pruproc_core {
	int idx;
	struct pruproc *pruproc;
	struct rproc *rproc;

	u32 pctrl;
	u32 pdbg;

	u32 iram[2];
	u32 dram[2];

	const char *fw_name;
	unsigned int is_elf : 1;
	u32 entry_point;

	struct resource_table *table;
	int table_size;
};

/* PRU control structure */
struct pruproc {
	struct platform_device *pdev;
	void __iomem *vaddr;
	dma_addr_t paddr;
	struct omap_mbox *mbox;
	struct notifier_block nb;
	u32 pintc;
	u32 pdram[2];	/* offset, size */

	int num_irqs;
	int irqs[MAX_ARM_PRU_INTS];
	int events[MAX_ARM_PRU_INTS];
	int sysev_to_ch[MAX_PRU_SYS_EVENTS];
	int ch_to_host[MAX_PRU_CHANNELS];

	/* number of prus */
	u32 num_prus;
	struct pruproc_core **pruc;
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
#define  CONTROL_SINGLE_STEP	0x0100
#define  CONTROL_RUNSTATE	0x4000

#define PCTRL_STATUS		0x0004
#define PCTRL_WAKEUP_EN		0x0008
#define PCTRL_CYCLE		0x000C
#define PCTRL_STALL		0x0010
#define PCTRL_CTBIR0		0x0020
#define PCTRL_CTBIR1		0x0024
#define PCTRL_CTPPR0		0x0028
#define PCTRL_CTPPR1		0x002C

/* PRU DEBUG */
#define PDBG_GPREG(x)		(0x0000 + (x) * 4)
#define PDBG_CT_REG(x)		(0x0080 + (x) * 4)

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
	return pru_read_reg(pp, reg + pp->pintc);
}

static inline void pintc_write_reg(struct pruproc *pp, unsigned int reg,
		u32 val)
{
	return pru_write_reg(pp, reg + pp->pintc, val);
}

static inline u32 pcntrl_read_reg(struct pruproc_core *ppc, unsigned int reg)
{
	return pru_read_reg(ppc->pruproc, reg + ppc->pctrl);
}

static inline void pcntrl_write_reg(struct pruproc_core *ppc, unsigned int reg,
		u32 val)
{
	return pru_write_reg(ppc->pruproc, reg + ppc->pctrl, val);
}

static inline u32 pdbg_read_reg(struct pruproc_core *ppc, unsigned int reg)
{
	return pru_read_reg(ppc->pruproc, reg + ppc->pdbg);
}

static inline void pdbg_write_reg(struct pruproc_core *ppc, unsigned int reg,
		u32 val)
{
	return pru_write_reg(ppc->pruproc, reg + ppc->pdbg, val);
}

static int pruproc_bin_sanity_check(struct rproc *rproc, const struct firmware *fw)
{
	return 0;
}

/* Loads the firmware to shared memory. */
static int pruproc_bin_load_segments(struct rproc *rproc, const struct firmware *fw)
{
	struct pruproc_core *ppc = rproc->priv;
	struct pruproc *pp = ppc->pruproc;
	struct device *dev = &rproc->dev;
	unsigned int max_size;
	void __iomem *va;

	pcntrl_write_reg(ppc, PCTRL_CONTROL, CONTROL_SOFT_RST_N);

	max_size = ppc->iram[1];
	if (fw->size > max_size) {
		dev_err(dev, "FW is larger than available space (%u > %u)\n",
				fw->size, max_size);
		return -ENOMEM;
	}

	va = pp->vaddr + ppc->iram[0];

	/* just copy */
	memcpy(va, fw->data, fw->size);

	/* binary starts from 0 */
	ppc->entry_point = 0;

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
	struct pruproc_core *ppc = rproc->priv;
	struct pruproc *pp = ppc->pruproc;
	struct elf32_hdr *ehdr;
	struct elf32_phdr *phdr;
	int i, ret = 0;
	const u8 *elf_data = fw->data;
	u32 da, memsz, filesz, offset, flags;
	u32 sect_offset, sect_maxsz;
	void *ptr;

	pcntrl_write_reg(ppc, PCTRL_CONTROL, CONTROL_SOFT_RST_N);

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
					(flags & PF_X) ? 'E' : '-');

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
			sect_offset = ppc->iram[0];
			sect_maxsz = ppc->iram[1];
		} else {
			/* only loading in local data ram */
			sect_offset = ppc->dram[0];
			sect_maxsz = ppc->dram[1];
		}

		/* check for overflow */
		if (da + memsz >= sect_maxsz) {
			dev_err(dev, "bad fw: does not fit in section\n");
			ret = -EINVAL;
		}

		ptr = pp->vaddr + sect_offset + da;

		/* put the segment where the remote processor expects it */
		if (filesz > 0)
			memcpy(ptr, elf_data + offset, filesz);
		else
			memset(ptr, 0, memsz);
	}

	ppc->entry_point = le32_to_cpu(ehdr->e_entry);

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
	struct pruproc_core *ppc = rproc->priv;

	*tablesz = ppc->table_size;
	return ppc->table;
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
	struct pruproc_core *ppc = rproc->priv;
	struct pruproc *pp = ppc->pruproc;
	struct device *dev = &pp->pdev->dev;

	dev_dbg(dev, "kick #%d vqid:%d\n", ppc->idx, vqid);
}

/* Start the PRU modem */
static int pruproc_start(struct rproc *rproc)
{
	struct pruproc_core *ppc = rproc->priv;
	struct pruproc *pp = ppc->pruproc;
	struct device *dev = &pp->pdev->dev;

	dev_dbg(dev, "start PRU #%d entry-point 0x%x\n",
			ppc->idx, ppc->entry_point);

	pcntrl_write_reg(ppc, PCTRL_CONTROL,
			CONTROL_ENABLE | ((ppc->entry_point >> 2) << 16));

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
	struct pruproc_core *ppc = rproc->priv;
	struct pruproc *pp = ppc->pruproc;
	struct device *dev = &pp->pdev->dev;
	void *va;

#if 0
	if (vring->da < PRU_SHARED_DATA_RAM ||
			vring->da >= PRU_SHARED_DATA_RAM + 0x3000) {
		dev_err(dev, "DA outside of shared DATA RAM\n");
		return NULL;
	}
#endif

	/* simple mapping (global=local) offset */
	va = pp->vaddr + vring->da;
	*dma = pp->paddr + vring->da;

	dev_dbg(dev, "%s: PRU #%d da=0x%x, va=%p, dma=0x%llx\n", __func__,
			ppc->idx, vring->da, va, (unsigned long long)*dma);
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
	struct pruproc_core *ppc;
	int i;

	dev_dbg(dev, "remove pru\n");

	/* Unregister as remoteproc device */
	for (i = pp->num_prus - 1; i >= 0; i--) {
		ppc = pp->pruc[i];
		rproc_del(ppc->rproc);
		rproc_put(ppc->rproc);
	}

	platform_set_drvdata(pdev, NULL);

	return 0;
}

#define PRU_HALT_INSN	0x2a000000

#define PRU_SC_HALT	0
#define PRU_SC_PUTC	1
#define PRU_SC_EXIT	2
#define PRU_SC_PUTS	3

static int pru_handle_syscall(struct pruproc_core *ppc)
{
	struct pruproc *pp = ppc->pruproc;
	struct device *dev = &pp->pdev->dev;
	u32 val, addr, scno, arg0;
	char *ptr;
	int valid_sc;

	/* check whether it's halted */
	val = pcntrl_read_reg(ppc, PCTRL_CONTROL);
	if ((val & CONTROL_RUNSTATE) != 0) {
		dev_dbg(dev, "PRU #%d not halted\n",
				ppc->idx);
		return -1;
	}

	/* read the instruction */
	addr = pcntrl_read_reg(ppc, PCTRL_STATUS);
	val = *(u32 *)(pp->vaddr + ppc->iram[0] + addr * 4);

	/* check whether it's a halt instruction */
	if (val != PRU_HALT_INSN) {
		dev_dbg(dev, "PRU #%d not in halt insn (addr=0x%x val 0x%08x)\n",
				ppc->idx, addr, val);
		return -1;
	}

	valid_sc = 0;
	scno = pdbg_read_reg(ppc, PDBG_GPREG(14));
	arg0 = pdbg_read_reg(ppc, PDBG_GPREG(15));
	switch (scno) {
		case PRU_SC_HALT:
			dev_dbg(dev, "PRU #%d SC HALT\n",
				ppc->idx);
			return 1;

		case PRU_SC_PUTC:
			dev_info(dev, "PRU #%d SC PUTC '%c'\n", 
				ppc->idx, (char)(arg0 & 0xff));
			break;

		case PRU_SC_EXIT:
			dev_dbg(dev, "PRU #%d SC EXIT %d\n",
				ppc->idx, (int)arg0);
			return 1;

		case PRU_SC_PUTS:
			/* pointers can only be in own data ram */
			if (arg0 >= ppc->dram[1]) {
				dev_err(dev, "PRU #%d SC PUTS bad 0x%x\n",
						arg0);
				return 1;
			}
			ptr = pp->vaddr + ppc->dram[0] + arg0;
			dev_dbg(dev, "PRU #%d SC PUTS %x (%s)\n",
				ppc->idx, (int)arg0, ptr);
			break;
		default:
			dev_dbg(dev, "PRU #%d SC Unknown (%d)\n",
				ppc->idx, scno);
			return 1;
	}

	/* skip over the HALT insn */
	val = pcntrl_read_reg(ppc, PCTRL_CONTROL);
	val &= 0xffff;
	val |= (addr + 1) << 16;
	val |= CONTROL_ENABLE;
	val &= ~CONTROL_SOFT_RST_N;

	/* dev_dbg(dev, "PRU#%d new PCTRL_CONTROL=0x%08x\n",
			ppc->idx, val); */

	pcntrl_write_reg(ppc, PCTRL_CONTROL, val);

	return 0;
}

static irqreturn_t pru_handler(int irq, void *data)
{
	struct pruproc *pp = data;
	struct pruproc_core *ppc;
	struct device *dev = &pp->pdev->dev;
	int i, ev, sysint, handled, ret;
	u32 val;

	/* find out which IRQ we got */
	for (i = 0; i < pp->num_irqs; i++)
		if (irq == pp->irqs[i])
			break;
	if (i >= pp->num_irqs)
		return IRQ_NONE;

	ev = pp->events[i];

	/* first, check whether the interrupt is enabled */
	val = pintc_read_reg(pp, PINTC_HIER);
	if ((val & (1 << ev)) == 0)
		return IRQ_NONE;

	/* check non-pending bit of specific event */
	val = pintc_read_reg(pp, PINTC_HIPIR0 + (ev << 2));
	if ((val & HIPIR_NOPEND) != 0)
		return IRQ_NONE;

	sysint = val & 0x3f;

	/* dev_dbg(dev, "Got interrupt #%d, event %d, sysint %d\n", irq, ev,
			sysint); */

	/* pump all the vrings */
	for (i = 0; i < pp->num_prus; i++) {
		ppc = pp->pruc[i];
	}

	/* now check if it's halted */
	handled = 0;
	for (i = 0; i < pp->num_prus; i++) {
		ppc = pp->pruc[i];

		ret = pru_handle_syscall(ppc);
		if (ret == 0) 	/* system call handled */
			handled++;

	}

	if (handled) {
		/* clear event */
		if (sysint < 32)
			pintc_write_reg(pp, PINTC_SECR0, 1 << sysint);
		else
			pintc_write_reg(pp, PINTC_SECR1, 1 << (sysint - 32));
	} else {

		dev_dbg(dev, "not handled; disabling interrupt\n");

		/* disable the interrupt */
		pintc_write_reg(pp, PINTC_HIDISR, ev);
	}

	return IRQ_HANDLED;
}

static int build_rsc_table(struct platform_device *pdev,
		struct device_node *node, struct pruproc_core *ppc)
{
	struct device *dev = &pdev->dev;
	struct device_node *rnode = NULL;	/* resource table node */
	struct device_node *rvnode = NULL;	/* vdev node */
	// struct pruproc *pp = ppc->pruproc;
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
	ppc->table = table;
	ppc->table_size = table_size;

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
		/* Use serial (dumb char device) for now */
		rsc_vdev->id = VIRTIO_ID_RPROC_SERIAL;
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

static int read_map_property(struct device *dev,
		struct device_node *node, const char *propname,
		int *map, int max_idx, int max_val)
{
	struct property *prop;
	int i, idx, val, cnt, proplen, err;
	u32 *arr, *p;

	/* check node & propname */
	if (node == NULL || propname == NULL) {
		dev_err(dev, "Bad arguments\n");
		return -EINVAL;
	}

	/* find property */
	prop = of_find_property(node, propname, &proplen);
	if (prop == NULL) {
		dev_err(dev, "Can't find %s property\n", propname);
		return -ENOENT;
	}

	/* verify valid size (must be pairs of u32 items) */
	if ((proplen % (sizeof(u32) * 2)) != 0) {
		dev_err(dev, "Bad length (%d) of %s property\n",
				proplen, propname);
		return -EINVAL;
	}

	/* allocate temporary buffer */
	arr = devm_kzalloc(dev, proplen, GFP_KERNEL);
	if (arr == NULL) {
		dev_err(dev, "Alloc failed on %s property\n", propname);
		return -ENOMEM;
	}

	/* the number of pairs */
	cnt = proplen / (sizeof(arr[0]) * 2);

	/* now read it */
	err = of_property_read_u32_array(node, propname, arr, cnt * 2);
	if (err != 0) {
		dev_err(dev, "Failed to read %s property\n", propname);
		return err;
	}

	/* now read pairs and fill in the map */
	for (i = 0, p = arr; i < cnt; i++, p += 2) {
		idx = p[0];
		val = p[1];
		if ((unsigned int)idx >= max_idx) {
			dev_err(dev, "%s[%d] bad map idx %d\n",
					propname, i, idx);
			return err;
		}
		if ((unsigned int)val >= max_val) {
			dev_err(dev, "%s[%d] bad map val %d\n",
					propname, i, val);
			return err;
		}
		/* fill in map */
		map[idx] = val;
		dev_info(dev, "%s [%d] <- %d\n", propname, idx, val);
	}

	devm_kfree(dev, arr);

	return 0;
}

static int configure_pintc(struct platform_device *pdev, struct pruproc *pp)
{
	struct device *dev = &pdev->dev;
	struct device_node *node = dev->of_node;
	int err, i, idx, ch, host;
	uint64_t sysevt_mask;
	uint32_t ch_mask;
	uint32_t host_mask;
	u32 val;

	/* retreive the maps */
	err = read_map_property(dev, node, "sysevent-to-channel-map",
			pp->sysev_to_ch, MAX_PRU_SYS_EVENTS, MAX_PRU_CHANNELS);
	if (err != 0)
		return err;

	err = read_map_property(dev, node, "channel-to-host-interrupt-map",
			pp->ch_to_host, MAX_PRU_CHANNELS, MAX_PRU_HOST_INT);
	if (err != 0)
		return err;

	/* now configure the pintc appropriately */

	/* configure polarity and type (all active high & pulse) */
	pintc_write_reg(pp, PINTC_SIPR0, 0xffffffff);
	pintc_write_reg(pp, PINTC_SIPR1, 0xffffffff);

	/* clear all channel mapping registers */
	for (i = PINTC_CMR0; i <= PINTC_CMR15; i += 4)
		pintc_write_reg(pp, i, 0);

	sysevt_mask = 0;
	ch_mask = 0;
	host_mask = 0;

	/* set channel mapping registers we have */
	for (i = 0; i < ARRAY_SIZE(pp->sysev_to_ch); i++) {

		ch = pp->sysev_to_ch[i];
		if (ch < 0)
			continue;

		/* CMR format: ---CH3---CH2---CH1---CH0 */

		/* 4 settings in each register */
		idx = i / 4;

		/* update CMR entry */
		val  = pintc_read_reg(pp, PINTC_CMR0 + idx * 4);
		val |= (u32)ch << ((i & 3) * 8);
		pintc_write_reg(pp, PINTC_CMR0 + idx * 4, val);

		/* set bit in the sysevent mask */
		sysevt_mask |= 1LLU << i;
		/* set bit in the channel mask */
		ch_mask |= 1U << ch;

		dev_dbg(dev, "SYSEV%d -> CH%d (CMR%d 0x%08x)\n",
				i, ch, idx,
				pintc_read_reg(pp, PINTC_CMR0 + idx * 4));
	}

	/* clear all host mapping registers */
	for (i = PINTC_HMR0; i <= PINTC_HMR2; i += 4)
		pintc_write_reg(pp, i, 0);

	/* set host mapping registers we have */
	for (i = 0; i < ARRAY_SIZE(pp->ch_to_host); i++) {

		host = pp->ch_to_host[i];
		if (host < 0)
			continue;

		/* HMR format: ---HI3---HI2---HI1---HI0 */

		/* 4 settings in each register */
		idx = i / 4;

		/* update HMR entry */
		val  = pintc_read_reg(pp, PINTC_HMR0 + idx * 4);
		val |= (u32)host << ((i & 3) * 8);
		pintc_write_reg(pp, PINTC_HMR0 + idx * 4, val);

		/* set bit in the channel mask */
		ch_mask |= 1U << i;
		/* set bit in the sysevent mask */
		host_mask |= 1U << host;

		dev_dbg(dev, "CH%d -> HOST%d (HMR%d 0x%08x)\n",
				i, host, idx,
				pintc_read_reg(pp, PINTC_HMR0 + idx * 4));
	}

	/* configure polarity and type (all active high & pulse) */
	pintc_write_reg(pp, PINTC_SITR0, 0);
	pintc_write_reg(pp, PINTC_SITR1, 0);

	dev_dbg(dev, "sysevt_mask=0x%016llx ch_mask=0x%08x host_mask=0x%08x\n",
			sysevt_mask, ch_mask, host_mask);

	/* enable sys-events */
	pintc_write_reg(pp, PINTC_ESR0, (u32)sysevt_mask);
	pintc_write_reg(pp, PINTC_SECR0, (u32)sysevt_mask);
	pintc_write_reg(pp, PINTC_ESR1, (u32)(sysevt_mask >> 32));
	pintc_write_reg(pp, PINTC_SECR1, (u32)(sysevt_mask >> 32));

	/* enable host interrupts */
	for (i = 0; i < MAX_PRU_HOST_INT; i++) {
		if ((host_mask & (1 << i)) != 0)
			pintc_write_reg(pp, PINTC_HIEISR, i);
	}

	/* global interrupt enable */
	pintc_write_reg(pp, PINTC_GER, 1);

	return 0;
}

static int pruproc_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *node = dev->of_node;
	struct device_node *pnode = NULL;
	struct pruproc *pp;
	struct pruproc_core *ppc;
	const char *fw_name;
	int pm_get = 0;
	struct rproc *rproc = NULL;
	struct resource *res;
	struct pinctrl *pinctrl;
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
	if (node == NULL) {
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

	pp = devm_kzalloc(dev, sizeof(*pp), GFP_KERNEL);
	if (pp == NULL) {
		dev_err(dev, "failed to allocate pruproc\n");
		err = -ENOMEM;
		goto err_fail;

	}

	/* link the device with the pruproc */
	platform_set_drvdata(pdev, pp);
	pp->pdev = pdev;

	/* prepare the irqs */
	for (i = 0; i < ARRAY_SIZE(pp->irqs); i++)
		pp->irqs[i] = -1;

	/* prepare the events */
	for (i = 0; i < ARRAY_SIZE(pp->events); i++)
		pp->events[i] = -1;

	/* prepare the sysevevent to channel map */
	for (i = 0; i < ARRAY_SIZE(pp->sysev_to_ch); i++)
		pp->sysev_to_ch[i] = -1;

	/* prepare the channel to hostint map */
	for (i = 0; i < ARRAY_SIZE(pp->ch_to_host); i++)
		pp->ch_to_host[i] = -1;

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
	dev_info(dev, "#%d PRU interrupts registered\n", pp->num_irqs);

	err = of_property_read_u32_array(node, "events", pp->events,
			pp->num_irqs);
	if (err != 0) {
		dev_err(dev, "Failed to read events array\n");
		goto err_fail;
	}

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

	err = of_property_read_u32(node, "pintc", &pp->pintc);
	if (err != 0) {
		dev_err(dev, "no pintc property\n");
		goto err_fail;
	}

	err = of_property_read_u32_array(node, "pdram", pp->pdram,
			ARRAY_SIZE(pp->pdram));
	if (err != 0) {
		dev_err(dev, "no pintc property\n");
		goto err_fail;
	}

	/* configure PRU interrupt controller from DT */ 
	err = configure_pintc(pdev, pp);
	if (err != 0) {
		dev_err(dev, "failed to configure pintc\n");
		goto err_fail;
	}

	/* count number of child nodes with a firmwary property */
	pp->num_prus = 0;
	for_each_child_of_node(node, pnode) {
		if (of_find_property(pnode, "firmware", NULL))
			pp->num_prus++;
	}
	pnode = NULL;

	/* found any? */
	if (pp->num_prus == 0) {
		dev_err(dev, "no pru nodes found\n");
		err = -EINVAL;
		goto err_fail;
	}
	dev_info(dev, "found #%d PRUs\n", pp->num_prus);

	/* allocate pointers */
	pp->pruc = devm_kzalloc(dev, sizeof(*pp->pruc) * pp->num_prus,
			GFP_KERNEL);
	if (pp->pruc == NULL) {
		dev_err(dev, "Failed to allocate PRU table\n");
		err = -ENOMEM;
		goto err_fail;
	}

	/* now iterate over all the pru nodes */
	i = 0;
	for_each_child_of_node(node, pnode) {

		/* only nodes with firmware are PRU nodes */
		if (of_find_property(pnode, "firmware", NULL) == NULL)
			continue;

		err = of_property_read_string(pnode, "firmware", &fw_name);
		if (err != 0) {
			dev_err(dev, "can't find fw property %s\n", "firmware");
			of_node_put(pnode);
			goto err_fail;
		}

		rproc = rproc_alloc(dev, pdev->name, &pruproc_ops, fw_name,
				sizeof(*ppc));
		if (!rproc) {
			dev_err(dev, "rproc_alloc failed\n");
			err = -ENOMEM;
			goto err_fail;
		}
		ppc = rproc->priv;
		ppc->idx = i;
		ppc->pruproc = pp;
		ppc->rproc = rproc;

		err = of_property_read_u32_array(pnode, "iram", ppc->iram,
				ARRAY_SIZE(ppc->iram));
		if (err != 0) {
			dev_err(dev, "no iram property\n");
			goto err_fail;
		}

		err = of_property_read_u32_array(pnode, "dram", ppc->dram,
				ARRAY_SIZE(ppc->dram));
		if (err != 0) {
			dev_err(dev, "no dram property\n");
			goto err_fail;
		}

		err = of_property_read_u32(pnode, "pctrl", &ppc->pctrl);
		if (err != 0) {
			dev_err(dev, "no pctrl property\n");
			goto err_fail;
		}

		err = of_property_read_u32(pnode, "pdbg", &ppc->pdbg);
		if (err != 0) {
			dev_err(dev, "no pdbg property\n");
			goto err_fail;
		}

		/* check firmware type */
		ppc->is_elf = of_property_read_bool(pnode, "firmware-elf");

		/* build the resource table from DT */
		err = build_rsc_table(pdev, pnode, ppc);
		if (err != 0) {
			dev_err(dev, "failed to build resource table\n");
			goto err_fail;
		}

		/* Set the PRU specific firmware handler */
		if (!ppc->is_elf)
			rproc->fw_ops = &pruproc_bin_fw_ops;
		else
			rproc->fw_ops = &pruproc_elf_fw_ops;

		/* Register as a remoteproc device */
		err = rproc_add(rproc);
		if (err) {
			dev_err(dev, "rproc_add failed\n");
			goto err_fail;
		}

		pp->pruc[i] = ppc;
		i++;
	}
	pnode = NULL;

	dev_info(dev, "Loaded OK\n");

	return 0;
err_fail:
	/* NULL is OK */
	of_node_put(pnode);

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
