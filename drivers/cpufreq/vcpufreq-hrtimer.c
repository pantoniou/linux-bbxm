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
#include <linux/hrtimer.h>

#include "vcpufreq.h"

struct hrtimer_info {
	unsigned int cpu;
	struct hrtimer hrtimer;
	ktime_t interval;
	unsigned int irq;
	uint64_t counter;
	unsigned int timer_rate;
	unsigned int hogtime;
};

static DEFINE_PER_CPU(struct hrtimer_info, hr_timer);

static enum hrtimer_restart vcpufreq_hrtimer_handler(struct hrtimer *hrtimer)
{
	struct hrtimer_info __percpu *hti = container_of(hrtimer, struct hrtimer_info, hrtimer);

	BUG_ON(hti == NULL);

	/* we rely on being executed on the proper CPU */
	BUG_ON(hti->cpu != smp_processor_id());

	hti->counter++;

	/*
	 * udelay is not always accurate for this;
	 * unfortunately that is all we have
	 */
	udelay(hti->hogtime);

	hrtimer_forward_now(hrtimer, hti->interval);

	return HRTIMER_RESTART;
}

struct vpcufreq_hr_timer_set_freq_info {
	unsigned int cpu;
	unsigned int new_freq;
	unsigned int old_freq;
	int ret;
};

static void hr_timer_glue_set_freq(void *data)
{
	struct vpcufreq_hr_timer_set_freq_info *info = data;
	struct hrtimer_info __percpu *hti;
	int ret = 0;
	unsigned int hog_timer_rate;
	unsigned int freq = vcpufreq_get_maxspeed();
	unsigned int hogtime = vcpufreq_get_hogtime();
	u32 div, rem;

	BUG_ON(smp_processor_id() != info->cpu);

	hti = &per_cpu(hr_timer, info->cpu);

	/* should never happen; checked before */
	BUG_ON(info->new_freq == info->old_freq);

	/* max freq; stop the timer */
	if (info->new_freq == freq) {
		pr_debug("#%d: shut down timer\n", info->cpu);
		/* no error */
		ret = 0;
		goto hr_stop_timer;

	}
	
	/* timer was stopped, we should start it */
	if (info->old_freq != freq)
		hrtimer_cancel(&hti->hrtimer);
	
	hog_timer_rate = div_u64((u64)(freq - info->new_freq) * 1000000, freq * hogtime);
	pr_debug("#%d: hog timer rate = %u\n", info->cpu, hog_timer_rate);

	div = div_u64_rem(1000000000 / hog_timer_rate, 1000000000, &rem);
	hti->interval = ktime_set(div, rem);
	hti->hogtime = hogtime;

	pr_debug("#%d: internal set to %usec %unsec\n", info->cpu, div, rem);

	/* timer bound to this CPU please */
	ret = hrtimer_start(&hti->hrtimer, hti->interval, HRTIMER_MODE_PINNED);
	if (ret != 0) {
		pr_err("#%d: failed to start hrtimer (%d)\n", info->cpu, ret);
		goto hr_stop_timer;
	}

	pr_debug("#%d: setting freq to %u\n", info->cpu, info->new_freq);

	vcpufreq_set_speed(info->cpu, info->new_freq);
	ret = 0;
	goto out;

hr_stop_timer:
	/* clear everything */

	hrtimer_cancel(&hti->hrtimer);

	/* always return to max speed here */
	vcpufreq_set_speed(info->cpu, freq);
out:
	info->ret = ret;
}

int vcpufreq_glue_set_freq(unsigned int cpu, unsigned int new_freq,
		unsigned int old_freq)
{
	struct vpcufreq_hr_timer_set_freq_info info;
	int ret;

	memset(&info, 0, sizeof(info));

	info.cpu = cpu;
	info.new_freq = new_freq;
	info.old_freq = old_freq;
	info.ret = -EINVAL;

	ret = smp_call_function_single(cpu, hr_timer_glue_set_freq, &info, 1);
	if (ret != 0) {
		pr_err("#%d: failed to call per CPU glue set freq\n", cpu);
		return ret;
	}

	if (info.ret != 0) {
		pr_err("#%d: failed to set freq\n", cpu);
		return info.ret;
	}

	return 0;
}

static void hr_timer_glue_init_cpu(void *info)
{
	struct hrtimer_info __percpu *hti;
	struct cpufreq_policy *policy = info;

	BUG_ON(policy == NULL);

	BUG_ON(smp_processor_id() != policy->cpu);

	hti = &per_cpu(hr_timer, policy->cpu);

	hrtimer_init(&hti->hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_PINNED);
	hti->hrtimer.function = vcpufreq_hrtimer_handler;

	pr_info("#%d: %s\n", policy->cpu, __func__);
}

int vcpufreq_glue_init(struct cpufreq_policy *policy, int *freq)
{
	struct hrtimer_info __percpu *hti;
	int ret = 0;

	BUG_ON(freq == NULL);

	if (*freq == 0) {
		*freq = 1000000;	/* simulated 1GHz */
	}

	/* initialize per cpu structure */
	hti = &per_cpu(hr_timer, policy->cpu);
	memset(hti, 0, sizeof(*hti));
	hti->cpu = policy->cpu;

	ret = smp_call_function_single(policy->cpu, hr_timer_glue_init_cpu, policy, 1);
	if (ret != 0) {
		pr_err("#%d: failed to call per CPU glue init\n", policy->cpu);
		goto error_out;
	}

	ret = 0;

error_out:
	return ret;
}

int vcpufreq_glue_exit(struct cpufreq_policy *policy)
{
	return 0;
}
