/*
 * AM33XX Power Management Routines
 *
 * Copyright (C) 2012 Texas Instruments Incorporated - http://www.ti.com/
 * Vaibhav Bedia <vaibhav.bedia@ti.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/firmware.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/sched.h>
#include <linux/suspend.h>
#include <linux/completion.h>
#include <linux/module.h>
#include <linux/mailbox.h>
#include <linux/interrupt.h>

#include <asm/suspend.h>
#include <asm/proc-fns.h>
#include <asm/sizes.h>
#include <asm/fncpy.h>
#include <asm/system_misc.h>

#include "pm.h"
#include "cm33xx.h"
#include "pm33xx.h"
#include "control.h"
#include "clockdomain.h"
#include "powerdomain.h"
#include "omap_hwmod.h"
#include "omap_device.h"
#include "soc.h"
#include "sram.h"

void (*am33xx_do_wfi_sram)(void);

static void __iomem *am33xx_emif_base;
static struct powerdomain *cefuse_pwrdm, *gfx_pwrdm, *per_pwrdm;
static struct clockdomain *gfx_l4ls_clkdm;
static struct omap_hwmod *usb_oh, *cpsw_oh, *tptc0_oh, *tptc1_oh, *tptc2_oh;
static struct wkup_m3_context *wkup_m3;

static DECLARE_COMPLETION(wkup_m3_sync);

#ifdef CONFIG_SUSPEND
static int am33xx_do_sram_idle(long unsigned int unused)
{
	am33xx_do_wfi_sram();
	return 0;
}

static int am33xx_pm_suspend(void)
{
	int status, ret = 0;

	/*
	 * By default the following IPs do not have MSTANDBY asserted
	 * which is necessary for PER domain transition. If the drivers
	 * are not compiled into the kernel HWMOD code will not change the
	 * state of the IPs if the IP was not never enabled. To ensure
	 * that there no issues with or without the drivers being compiled
	 * in the kernel, we forcefully put these IPs to idle.
	 */
	omap_hwmod_enable(usb_oh);
	omap_hwmod_enable(tptc0_oh);
	omap_hwmod_enable(tptc1_oh);
	omap_hwmod_enable(tptc2_oh);
	omap_hwmod_enable(cpsw_oh);

	omap_hwmod_idle(usb_oh);
	omap_hwmod_idle(tptc0_oh);
	omap_hwmod_idle(tptc1_oh);
	omap_hwmod_idle(tptc2_oh);
	omap_hwmod_idle(cpsw_oh);

	/* Try to put GFX to sleep */
	pwrdm_set_next_fpwrst(gfx_pwrdm, PWRDM_FUNC_PWRST_OFF);

	ret = cpu_suspend(0, am33xx_do_sram_idle);

	status = pwrdm_read_fpwrst(gfx_pwrdm);
	if (status != PWRDM_FUNC_PWRST_OFF)
		pr_err("GFX domain did not transition\n");
	else
		pr_info("GFX domain entered low power state\n");

	/*
	 * GFX_L4LS clock domain needs to be woken up to
	 * ensure thet L4LS clock domain does not get stuck in transition
	 * If that happens L3 module does not get disabled, thereby leading
	 * to PER power domain transition failing
	 *
	 * The clock framework should take care of ensuring
	 * that the clock domain is in the right state when
	 * GFX driver is active.
	 */
	clkdm_wakeup(gfx_l4ls_clkdm);
	clkdm_sleep(gfx_l4ls_clkdm);

	if (ret) {
		pr_err("Kernel suspend failure\n");
	} else {
		status = omap_ctrl_readl(AM33XX_CONTROL_IPC_MSG_REG1);
		status &= IPC_RESP_MASK;
		status >>= __ffs(IPC_RESP_MASK);

		switch (status) {
		case 0:
			pr_info("Successfully put all powerdomains to target state\n");
			/*
			 * XXX: Leads to loss of logic state in PER power domain
			 * Use SOC specific ops for this?
			 */
			break;
		case 1:
			pr_err("Could not transition all powerdomains to target state\n");
			ret = -1;
			break;
		default:
			pr_err("Something went wrong :(\nStatus = %d\n",
				status);
			ret = -1;
		}
	}

	return ret;
}

static int am33xx_pm_enter(suspend_state_t suspend_state)
{
	int ret = 0;

	switch (suspend_state) {
	case PM_SUSPEND_STANDBY:
	case PM_SUSPEND_MEM:
		ret = am33xx_pm_suspend();
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static int am33xx_pm_begin(suspend_state_t state)
{
	int ret = 0;
	struct mailbox_msg dummy_msg;

	disable_hlt();

	MAILBOX_FILL_HEADER_MSG(dummy_msg, 0xABCDABCD);

	wkup_m3->ipc_data.sleep_mode = IPC_CMD_DS0;
	wkup_m3->ipc_data.param1  = DS_IPC_DEFAULT;
	wkup_m3->ipc_data.param2  = DS_IPC_DEFAULT;

	am33xx_wkup_m3_ipc_cmd(&wkup_m3->ipc_data);

	wkup_m3->state = M3_STATE_MSG_FOR_LP;

	mailbox_enable_irq(wkup_m3->mbox, IRQ_RX);

	ret = mailbox_msg_send(wkup_m3->mbox, &dummy_msg);
	if (ret) {
		pr_err("A8<->CM3 MSG for LP failed\n");
		am33xx_m3_state_machine_reset();
		ret = -1;
	}

	/* Give some time to M3 to respond. 500msec is a random value here */
	if (!wait_for_completion_timeout(&wkup_m3_sync,
					msecs_to_jiffies(500))) {
		pr_err("A8<->CM3 sync failure\n");
		am33xx_m3_state_machine_reset();
		ret = -1;
	} else {
		pr_debug("Message sent for entering DeepSleep mode\n");
		mailbox_disable_irq(wkup_m3->mbox, IRQ_RX);
	}

	return ret;
}

static void am33xx_pm_end(void)
{
	mailbox_enable_irq(wkup_m3->mbox, IRQ_RX);

	am33xx_m3_state_machine_reset();

	enable_hlt();

	return;
}

static const struct platform_suspend_ops am33xx_pm_ops = {
	.begin		= am33xx_pm_begin,
	.end		= am33xx_pm_end,
	.enter		= am33xx_pm_enter,
	.valid		= suspend_valid_only_mem,
};

static void am33xx_m3_state_machine_reset(void)
{
	int ret = 0;
	struct mailbox_msg dummy_msg;

	MAILBOX_FILL_HEADER_MSG(dummy_msg, 0xABCDABCD);

	wkup_m3->ipc_data.sleep_mode	= IPC_CMD_RESET;
	wkup_m3->ipc_data.param1	= DS_IPC_DEFAULT;
	wkup_m3->ipc_data.param2	= DS_IPC_DEFAULT;

	am33xx_wkup_m3_ipc_cmd(&wkup_m3->ipc_data);

	wkup_m3->state = M3_STATE_MSG_FOR_RESET;

	ret = mailbox_msg_send(wkup_m3->mbox, &dummy_msg);
	if (!ret) {
		pr_debug("Message sent for resetting M3 state machine\n");
		/* Give some to M3 to respond. 500msec is a random value here */
		if (!wait_for_completion_timeout(&wkup_m3_sync,
						msecs_to_jiffies(500)))
			pr_err("A8<->CM3 sync failure\n");
	} else {
		pr_err("Could not reset M3 state machine!!!\n");
		wkup_m3->state = M3_STATE_UNKNOWN;
	}
}
#endif /* CONFIG_SUSPEND */

/*
 * Dummy notifier for the mailbox
 * XXX: Get rid of this requirement once the MBX driver has been finalized
 */
static int wkup_mbox_msg(struct notifier_block *self, unsigned long len,
		void *msg)
{
	return 0;
}

static struct notifier_block wkup_mbox_notifier = {
	.notifier_call = wkup_mbox_msg,
};

static irqreturn_t wkup_m3_txev_handler(int irq, void *unused)
{
	am33xx_txev_eoi();

	switch (wkup_m3->state) {
	case M3_STATE_RESET:
		wkup_m3->state = M3_STATE_INITED;
		break;
	case M3_STATE_MSG_FOR_RESET:
		wkup_m3->state = M3_STATE_INITED;
		mailbox_rx_flush(wkup_m3->mbox);
		complete(&wkup_m3_sync);
		break;
	case M3_STATE_MSG_FOR_LP:
		mailbox_rx_flush(wkup_m3->mbox);
		complete(&wkup_m3_sync);
		break;
	case M3_STATE_UNKNOWN:
		pr_err("IRQ %d with WKUP_M3 in unknown state\n", irq);
		mailbox_rx_flush(wkup_m3->mbox);
		return IRQ_NONE;
	}

	am33xx_txev_enable();
	return IRQ_HANDLED;
}

static void am33xx_pm_firmware_cb(const struct firmware *fw, void *context)
{
	struct wkup_m3_context *wkup_m3_context = context;
	struct platform_device *pdev = to_platform_device(wkup_m3_context->dev);
	int ret = 0;

	/* no firmware found */
	if (!fw) {
		dev_err(wkup_m3_context->dev, "request_firmware failed\n");
		goto err;
	}

	memcpy((void *)wkup_m3_context->code, fw->data, fw->size);
	pr_info("Copied the M3 firmware to UMEM\n");

	wkup_m3->state = M3_STATE_RESET;

	ret = omap_device_deassert_hardreset(pdev, "wkup_m3");
	if (ret) {
		pr_err("Could not deassert the reset for WKUP_M3\n");
		goto err;
	} else {
#ifdef CONFIG_SUSPEND
		suspend_set_ops(&am33xx_pm_ops);
		/*
		 * Physical resume address to be used by ROM code
		 */
		wkup_m3->ipc_data.resume_addr = (AM33XX_OCMC_END -
				am33xx_do_wfi_sz + am33xx_resume_offset + 0x4);
#endif
		return;
	}

err:
	mailbox_put(wkup_m3_context->mbox, &wkup_mbox_notifier);
}

static int wkup_m3_init(void)
{
	int irq, ret = 0;
	struct resource *mem;
	struct platform_device *pdev = to_platform_device(wkup_m3->dev);

	omap_device_enable_hwmods(to_omap_device(pdev));

	/* Reserve the MBOX for sending messages to M3 */
	wkup_m3->mbox = mailbox_get("wkup_m3", &wkup_mbox_notifier);
	if (IS_ERR(wkup_m3->mbox)) {
		pr_err("Could not reserve mailbox for A8->M3 IPC\n");
		ret = -ENODEV;
		goto exit;
	}

	irq = platform_get_irq(pdev, 0);
	if (!irq) {
		dev_err(wkup_m3->dev, "no irq resource\n");
		ret = -ENXIO;
		goto err;
	}

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!mem) {
		dev_err(wkup_m3->dev, "no memory resource\n");
		ret = -ENXIO;
		goto err;
	}

	wkup_m3->code = devm_request_and_ioremap(wkup_m3->dev, mem);
	if (!wkup_m3->code) {
		dev_err(wkup_m3->dev, "could not ioremap\n");
		ret = -EADDRNOTAVAIL;
		goto err;
	}

	ret = devm_request_irq(wkup_m3->dev, irq, wkup_m3_txev_handler,
		  IRQF_DISABLED, "wkup_m3_txev", NULL);
	if (ret) {
		dev_err(wkup_m3->dev, "request_irq failed\n");
		goto err;
	} else {
		am33xx_txev_enable();
	}

	pr_info("Trying to load am335x-pm-firmware.bin");

	/* We don't want to delay boot */
	request_firmware_nowait(THIS_MODULE, 0, "am335x-pm-firmware.bin",
				wkup_m3->dev, GFP_KERNEL, wkup_m3,
				am33xx_pm_firmware_cb);
	return 0;

err:
	mailbox_put(wkup_m3->mbox, &wkup_mbox_notifier);
exit:
	return ret;
}

/*
 * Push the minimal suspend-resume code to SRAM
 */
void am33xx_push_sram_idle(void)
{
	am33xx_do_wfi_sram = (void *)omap_sram_push
					(am33xx_do_wfi, am33xx_do_wfi_sz);
}

static int __init am33xx_map_emif(void)
{
	am33xx_emif_base = ioremap(AM33XX_EMIF_BASE, SZ_32K);

	if (!am33xx_emif_base)
		return -ENOMEM;

	return 0;
}

void __iomem *am33xx_get_emif_base(void)
{
	return am33xx_emif_base;
}

int __init am33xx_pm_init(void)
{
	int ret;

	if (!soc_is_am33xx())
		return -ENODEV;

	pr_info("Power Management for AM33XX family\n");

	/*
	 * By default the following IPs do not have MSTANDBY asserted
	 * which is necessary for PER domain transition. If the drivers
	 * are not compiled into the kernel HWMOD code will not change the
	 * state of the IPs if the IP was not never enabled
	 */
	usb_oh		= omap_hwmod_lookup("usb_otg_hs");
	tptc0_oh	= omap_hwmod_lookup("tptc0");
	tptc1_oh	= omap_hwmod_lookup("tptc1");
	tptc2_oh	= omap_hwmod_lookup("tptc2");
	cpsw_oh		= omap_hwmod_lookup("cpgmac0");

	gfx_pwrdm = pwrdm_lookup("gfx_pwrdm");
	per_pwrdm = pwrdm_lookup("per_pwrdm");

	gfx_l4ls_clkdm = clkdm_lookup("gfx_l4ls_gfx_clkdm");

	if ((!usb_oh) || (!tptc0_oh) || (!tptc1_oh) || (!tptc2_oh) ||
		(!cpsw_oh) || (!gfx_pwrdm) || (!per_pwrdm) ||
		(!gfx_l4ls_clkdm)) {
		ret = -ENODEV;
		goto err;
	}

	wkup_m3 = kzalloc(sizeof(struct wkup_m3_context), GFP_KERNEL);
	if (!wkup_m3) {
		pr_err("Memory allocation failed\n");
		ret = -ENOMEM;
		goto err;
	}

	ret = am33xx_map_emif();
	if (ret) {
		pr_err("Could not ioremap EMIF\n");
		goto err;
	}

	(void) clkdm_for_each(omap_pm_clkdms_setup, NULL);

	/* CEFUSE domain can be turned off post bootup */
	cefuse_pwrdm = pwrdm_lookup("cefuse_pwrdm");
	if (cefuse_pwrdm)
		pwrdm_set_next_fpwrst(cefuse_pwrdm, PWRDM_FUNC_PWRST_OFF);
	else
		pr_err("Failed to get cefuse_pwrdm\n");

	wkup_m3->dev = omap_device_get_by_hwmod_name("wkup_m3");

	ret = wkup_m3_init();
	if (ret)
		pr_err("Could not initialise firmware loading\n");

err:
	return ret;
}
