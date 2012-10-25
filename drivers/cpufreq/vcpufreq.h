#ifndef __VCPUFREQ_H
#define __VCPUFREQ_H

/*
 * Copyright 2012 Pantelis Antoniou <panto@antoniou-consulting.com>
 *
 * Virtual CPUFreq driver header.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* provided by the glue layer */
int vcpufreq_glue_set_freq(unsigned int cpu, unsigned int new_freq,
		unsigned int old_freq);
int vcpufreq_glue_init(struct cpufreq_policy *policy, int *freq);
int vcpufreq_glue_exit(struct cpufreq_policy *policy);

/* provided by the core */
unsigned int vcpufreq_get_maxspeed(void);
unsigned int vcpufreq_get_hogtime(void);
void vcpufreq_set_speed(unsigned int cpu, unsigned int new_freq);

#endif
