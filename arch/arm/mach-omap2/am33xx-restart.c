/*
 * am33xx-restart.c - Code common to all AM33xx machines.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/init.h>

#include "iomap.h"
#include "common.h"
#include "control.h"
#include "prm33xx.h"

/**
 * am3xx_restart - trigger a software restart of the SoC
 * @mode: the "reboot mode", see arch/arm/kernel/{setup,process}.c
 * @cmd: passed from the userspace program rebooting the system (if provided)
 *
 * Resets the SoC.  For @cmd, see the 'reboot' syscall in
 * kernel/sys.c.  No return value.
 */
void am33xx_restart(char mode, const char *cmd)
{
	u32 v;

        // TODO: Handle mode and cmd

	v = am33xx_prm_read_reg(AM33XX_PRM_DEVICE_MOD,
				AM33XX_PRM_RSTCTRL_OFFSET);
	v |= 1;
	am33xx_prm_write_reg(v, AM33XX_PRM_DEVICE_MOD,
				 AM33XX_PRM_RSTCTRL_OFFSET);

	/* OCP barrier */
	v = am33xx_prm_read_reg(AM33XX_PRM_DEVICE_MOD,
				    AM33XX_PRM_RSTCTRL_OFFSET);
	while (1);
}
