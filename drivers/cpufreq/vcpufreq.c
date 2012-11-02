/*
 * Copyright 2012 Pantelis Antoniou <panto@antoniou-consulting.com>
 *
 * Virtual CPUFreq driver; allows usage of normal SMP systems for
 * asymmetric processing evaluation.
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

#include "vcpufreq.h"

static struct cpufreq_frequency_table *vfreq_table = NULL;

static unsigned int latency = 500;
static unsigned int splits = 2;
static unsigned int freq = 0;	/* default 1GHz */
static unsigned int hogtime = 100;

/* HMP fields */
static struct cpumask fast_mask;
static unsigned int fast_freq, slow_freq;

struct vcpufreq_data {
	unsigned int max_freq;
	unsigned int max_cpu_power;
	unsigned int cur_freq;
};

static DEFINE_PER_CPU(struct vcpufreq_data, vcf_data);

static int vcpufreq_verify_speed(struct cpufreq_policy *policy)
{
	BUG_ON(vfreq_table == NULL);
	return cpufreq_frequency_table_verify(policy, vfreq_table);
}

unsigned int vcpufreq_get_speed(unsigned int cpu)
{
	return per_cpu(vcf_data, cpu).cur_freq;
}

void vcpufreq_set_speed(unsigned int cpu, unsigned int new_freq)
{
	per_cpu(vcf_data, cpu).cur_freq = new_freq;
}

unsigned int vcpufreq_get_maxspeed(unsigned int cpu)
{
	return per_cpu(vcf_data, cpu).max_freq;
}

unsigned int vcpufreq_get_hogtime(void)
{
	return hogtime;
}

unsigned int vcpufreq_get_max_cpu_power(unsigned int cpu)
{
	return per_cpu(vcf_data, cpu).max_cpu_power;
}

static int vcpufreq_set_target(struct cpufreq_policy *policy,
				      unsigned int target_freq,
				      unsigned int relation)
{
	int ret;
	unsigned int i;
	struct cpufreq_freqs freqs;

	BUG_ON(vfreq_table == NULL);

	ret = cpufreq_frequency_table_target(policy, vfreq_table,
					     target_freq, relation, &i);
	if (ret != 0)
		return ret;

	memset(&freqs, 0, sizeof(freqs));
	freqs.cpu = policy->cpu;
	freqs.old = vcpufreq_get_speed(policy->cpu);
	freqs.new = vfreq_table[i].frequency;

	if (freqs.old == freqs.new && policy->cur == freqs.new)
		return 0;

	/* the CPUs are free-clocked */
	freqs.cpu = policy->cpu;
	cpufreq_notify_transition(&freqs, CPUFREQ_PRECHANGE);

	pr_debug("Transition %d-%dkHz\n", freqs.old, freqs.new);

	/* nothing */
	if (freqs.new == freqs.old) {
		pr_err("#%d: same freq %u\n", policy->cpu, freqs.new);
		ret = -EAGAIN;
		goto error_out;
	}

	ret = vcpufreq_glue_set_freq(policy->cpu, freqs.new, freqs.old);

error_out:
	cpufreq_notify_transition(&freqs, CPUFREQ_POSTCHANGE);

	return ret;
}

static int __cpuinit vcpufreq_driver_init(struct cpufreq_policy *policy)
{
	int ret;
	unsigned int i;
	unsigned int max_freq;

	max_freq = per_cpu(vcf_data, policy->cpu).max_freq;
	ret = vcpufreq_glue_init(policy, &max_freq);
	if (ret != 0) {
		pr_err("%s: vcpufreq_glue_init() failed\n", __func__);
		goto error_out;
	}
	per_cpu(vcf_data, policy->cpu).max_freq = max_freq;

	if (splits < 1) {
		pr_err("%s: Illegal splits value (%u)\n", __func__, splits);
		ret = -EINVAL;
		goto error_out;
	}

	vfreq_table = kmalloc(sizeof(*vfreq_table) * (splits + 1), GFP_KERNEL);
	if (vfreq_table == NULL) {
		pr_err("Failed to allocate frequency table: %d\n",
		       ret);
		ret = -ENOMEM;
		goto error_out;
	}

	/* 0 .. splits-1 */
	for (i = 0; i < splits; i++) {
		vfreq_table[i].index = i;
		vfreq_table[i].frequency = (max_freq * (i + 1)) / splits;
	}
	/* splits-1 */
	vfreq_table[i].index = i;
	vfreq_table[i].frequency = max_freq;

	/* ends */
	vfreq_table[i].index = i;
	vfreq_table[i].frequency = CPUFREQ_TABLE_END;

	ret = cpufreq_frequency_table_cpuinfo(policy, vfreq_table);
	if (ret != 0) {
		pr_err("Failed to configure frequency table: %d\n",
		       ret);
		goto error_out;
	}

	cpufreq_frequency_table_get_attr(vfreq_table, policy->cpu);

	policy->min = policy->cpuinfo.min_freq;
	policy->max = policy->cpuinfo.max_freq;

	/* always start at the max */
	per_cpu(vcf_data, policy->cpu).cur_freq =
		per_cpu(vcf_data, policy->cpu).max_freq;

	policy->cur = per_cpu(vcf_data, policy->cpu).cur_freq;
	policy->cpuinfo.transition_latency = latency;

	/* initial */
	vcpufreq_glue_set_freq(policy->cpu, policy->cur, 0);

	pr_info("#%d: Virtual CPU frequency driver initialized\n", policy->cpu);

	return 0;

error_out:
	kfree(vfreq_table);
	vfreq_table = NULL;
	return ret;
}

static int __cpuexit vcpufreq_driver_exit(struct cpufreq_policy *policy)
{
	kfree(vfreq_table);
	vfreq_table = NULL;
	vcpufreq_glue_exit(policy);

	return 0;
}

static struct freq_attr *vcpufreq_attr[] = {
	&cpufreq_freq_attr_scaling_available_freqs,
	NULL,
};

static struct cpufreq_driver vcpufreq_driver = {
	.owner		= THIS_MODULE,
	.flags          = CPUFREQ_CONST_LOOPS,
	.verify		= vcpufreq_verify_speed,
	.target		= vcpufreq_set_target,
	.get		= vcpufreq_get_speed,
	.init		= vcpufreq_driver_init,
	.exit		= vcpufreq_driver_exit,
	.name		= "vcpufreq",
	.attr		= vcpufreq_attr,
};

struct sched_domain;
extern unsigned long arch_scale_freq_power(struct sched_domain *sd, int cpu);

static int __init vcpufreq_init(void)
{
	unsigned int cpu;

#if defined(CONFIG_HMP_FAST_CPU_MASK) && defined(CONFIG_HMP_SLOW_CPU_MASK)
	fast_freq = simple_strtoul(CONFIG_HMP_FAST_MAX_FREQ, NULL, 10) * 1000;
	slow_freq = simple_strtoul(CONFIG_HMP_SLOW_MAX_FREQ, NULL, 10) * 1000;
	cpumask_clear(&fast_mask);
	if (cpulist_parse(CONFIG_HMP_FAST_CPU_MASK, &fast_mask)) {
		WARN(1, "Failed to parse HMP fast cpu mask!\n");
		cpumask_setall(&fast_mask);	/* set all to fast */
		slow_freq = fast_freq;
	}
#else
	cpumask_set(&fast_mask);
	fast_freq = slow_freq = freq;
#endif

	/* collect info about the maximum capacity of the CPUs */
	for_each_possible_cpu(cpu) {
		if (cpumask_test_cpu(cpu, &fast_mask))
			per_cpu(vcf_data, cpu).max_freq = fast_freq;
		else
			per_cpu(vcf_data, cpu).max_freq = slow_freq;
		per_cpu(vcf_data, cpu).max_cpu_power =
			arch_scale_freq_power(NULL, cpu);
		printk(KERN_INFO "vcpufreq: cpu%d "
				"max_cpu_power=%u max_freq=%u\n", cpu,
				per_cpu(vcf_data, cpu).max_cpu_power,
				per_cpu(vcf_data, cpu).max_freq);
	}

	return cpufreq_register_driver(&vcpufreq_driver);
}
module_init(vcpufreq_init);

module_param(latency, uint, 0644);
MODULE_PARM_DESC(latency, "Transition latency in usecs (default 500)");

module_param(splits, uint, 0644);
MODULE_PARM_DESC(splits, "Number of frequency splits (default 2)");

module_param(freq, uint, 0644);
MODULE_PARM_DESC(freq, "Maximum frequency in kHz (0 means platform detect)");

module_param(hogtime, uint, 0644);
MODULE_PARM_DESC(hogtime, "Time spend hogging the CPU in the IRQ handle in usec (default 10)");
