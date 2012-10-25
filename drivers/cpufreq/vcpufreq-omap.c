/*
 * Copyright 2012 Pantelis Antoniou <panto@antoniou-consulting.com>
 *
 * Virtual CPUFreq glue driver for OMAP2PLUS
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) "cpufreq: " fmt

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/cpufreq.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/math64.h>
#include <linux/delay.h>

#include <asm/smp_plat.h>
#include <asm/cpu.h>
#include <plat/cpu.h>
#include <plat/dmtimer.h>	

#include "vcpufreq.h"

struct omap_timer_info {
	unsigned int cpu;
	struct omap_dm_timer *dm_timer;
	unsigned int irq;
	uint64_t counter;
	char irqname[16];	/* vcpufreq%d */
	unsigned int hwtimer_rate;
	unsigned int hog_delta;
};

static DEFINE_PER_CPU(struct omap_timer_info, vcpufreq_omap_timer);

static irqreturn_t dm_timer_handler(int irq, void *dev_id)
{
	struct omap_timer_info *oti = dev_id;
	unsigned int status;
	unsigned int start;

	BUG_ON(oti == NULL);
	BUG_ON(oti->dm_timer == NULL);

	status = omap_dm_timer_read_status(oti->dm_timer);
	if (status & OMAP_TIMER_INT_OVERFLOW) {
		omap_dm_timer_write_status(oti->dm_timer,
				OMAP_TIMER_INT_OVERFLOW);
		omap_dm_timer_read_status(oti->dm_timer);
		oti->counter++;

		/*
		 * udelay is really crap for this; no accuracy whatsoever
		 * so use the nice hardware counter and be happy
		 */
		start = omap_dm_timer_read_counter(oti->dm_timer);
		while ((omap_dm_timer_read_counter(oti->dm_timer) - start)
				< oti->hog_delta)
			;	/* do nothing */

		return IRQ_HANDLED;
	}

	return IRQ_NONE;
}

int vcpufreq_glue_set_freq(unsigned int cpu, unsigned int new_freq,
		unsigned int old_freq)
{
	struct omap_timer_info __percpu *oti = &per_cpu(vcpufreq_omap_timer, cpu);
	int ret = 0;
	uint32_t rate;
	unsigned int hog_timer_rate;
	unsigned int freq = vcpufreq_get_maxspeed();
	unsigned int hogtime = vcpufreq_get_hogtime();

	/* should never happen; checked before */
	BUG_ON(new_freq == old_freq);

	/* max freq; stop the timer */
	if (new_freq == freq) {
		pr_debug("#%d: shut down timer\n", cpu);
		/* no error */
		ret = 0;
		goto omap_stop_timer;

	}
	
	/* timer was stopped, we should start it */
	if (old_freq == freq) {

		oti->cpu = cpu;

		/* get any omap timer */
		oti->dm_timer = omap_dm_timer_request();
		if (oti->dm_timer == NULL) {
			pr_err("#%d: No available omap timers\n", cpu);
			ret = -ENODEV;
			goto omap_stop_timer;
		}

		pr_debug("#%d: got omap timer with irq %d\n", cpu, oti->dm_timer->irq);

		/* source it from SYS_CLK */
		ret = omap_dm_timer_set_source(oti->dm_timer, OMAP_TIMER_SRC_SYS_CLK);
		if (ret != 0) {
			pr_err("#%d: omap_dm_timer_set_source() failed\n", cpu);
			goto omap_stop_timer;
		}

		/* set the prescaler to 0 (need a fast timer) */
		ret = omap_dm_timer_set_prescaler(oti->dm_timer, 0);
		if (ret != 0) {
			pr_err("#%d: omap_dm_timer_set_prescaler() failed\n", cpu);
			goto omap_stop_timer;
		}

		/* get the irq */
		ret = omap_dm_timer_get_irq(oti->dm_timer);
		if (ret < 0) {
			pr_err("#%d: omap_dm_timer_get_irq() failed\n", cpu);
			goto omap_stop_timer;
		}
		oti->irq = ret;

		snprintf(oti->irqname, sizeof(oti->irqname), "vcpufreq%u", cpu);
		ret = request_irq(oti->irq, dm_timer_handler,
				IRQF_DISABLED | IRQF_TIMER, oti->irqname, oti);
		if (ret < 0) {
			pr_err("#%d: failed to request percpu irq %d (%d)\n", cpu,
					oti->irq, ret);
			goto omap_stop_timer;
		}
	} else
		omap_dm_timer_stop(oti->dm_timer);
	
	/* common in either case */
	oti->hwtimer_rate = clk_get_rate(omap_dm_timer_get_fclk(oti->dm_timer));
	if (oti->hwtimer_rate == 0) {
		pr_err("#%d: illegal timer fclk rate\n", cpu);
		goto omap_stop_timer;
	}
	pr_debug("#%d: hwtimer_rate=%u/sec (period %uns)", cpu,
			oti->hwtimer_rate, 1000000000 / oti->hwtimer_rate);

	oti->hog_delta = div_u64((u64)oti->hwtimer_rate * (u64)hogtime, 1000000);
	pr_debug("#%d: hog_delta = %u\n", cpu, oti->hog_delta);

	/* rate of hog timer */
	hog_timer_rate = div_u64((u64)(freq - new_freq) * 1000000, freq * hogtime);
	pr_debug("#%d: hog timer rate = %u\n", cpu, hog_timer_rate);

	rate = (oti->hwtimer_rate + (hog_timer_rate / 2)) / hog_timer_rate;
	pr_debug("#%d: hw timer rate = %u\n", cpu, rate);

	omap_dm_timer_set_load(oti->dm_timer, 1, 0xFFFFFFFF - rate);

	/* first start */
	if (old_freq == freq) {
		/* enable the interrupt on overflow */
		omap_dm_timer_set_int_enable(oti->dm_timer,
				OMAP_TIMER_INT_OVERFLOW);
		/* route the interrupt to a given cpu */
		irq_set_affinity(oti->irq, cpumask_of(cpu));
	}

	omap_dm_timer_start(oti->dm_timer);

	vcpufreq_set_speed(cpu, new_freq);
	return 0;

omap_stop_timer:
	/* clear everything */
	if (oti->dm_timer) {

		omap_dm_timer_stop(oti->dm_timer);
		if (oti->irq != (unsigned int)-1) {
			free_irq(oti->irq, oti);
			oti->irq = -1;
		}
		omap_dm_timer_free(oti->dm_timer);

		/* clean up */
		memset(oti, 0, sizeof(*oti));
		oti->irq = (unsigned int)-1;
	}

	/* always return to max speed here */
	vcpufreq_set_speed(cpu, freq);
	return ret;
}

int vcpufreq_glue_init(struct cpufreq_policy *policy, int *freq)
{
	struct omap_timer_info __percpu *oti;
	int ret = 0;
	struct clk *mpu_clk;
	const char *mpu_clk_name = NULL;

	BUG_ON(freq == NULL);

	/* if no freq was provided, probe */
	if (*freq == 0) {
		if (cpu_is_omap24xx())
			mpu_clk_name = "virt_prcm_set";
		else if (cpu_is_omap34xx())
			mpu_clk_name = "dpll1_ck";
		else if (cpu_is_omap44xx())
			mpu_clk_name = "dpll_mpu_ck";

		if (mpu_clk_name == NULL) {
			pr_err("%s: Unknown mpu_clk_name (unsupported)\n",
					__func__);
			ret = -EINVAL;
			goto error_out;
		}
		mpu_clk = clk_get(NULL, mpu_clk_name);
		if (IS_ERR(mpu_clk)) {
			ret = PTR_ERR(mpu_clk);
			pr_err("%s: clk_get for '%s' failed\n", __func__,
					mpu_clk_name);
			goto error_out;
		}
		/* update freq */
		*freq = clk_get_rate(mpu_clk) / 1000;
	}

	/* initialize per cpu structure */
	oti = &per_cpu(vcpufreq_omap_timer, policy->cpu);
	memset(oti, 0, sizeof(*oti));
	oti->irq = (unsigned int)-1;

	ret = 0;

error_out:
	return ret;
}

int vcpufreq_glue_exit(struct cpufreq_policy *policy)
{
	return 0;
}
