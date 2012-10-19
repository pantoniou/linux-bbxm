#include "builtin.h"
#include "perf.h"

#include "util/util.h"
#include "util/evlist.h"
#include "util/cache.h"
#include "util/evsel.h"
#include "util/symbol.h"
#include "util/thread.h"
#include "util/header.h"
#include "util/session.h"
#include "util/tool.h"

#include "util/parse-options.h"
#include "util/trace-event.h"

#include "util/debug.h"

#include <sys/prctl.h>
#include <sys/resource.h>

#include <semaphore.h>
#include <pthread.h>
#include <math.h>

#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <sys/time.h>

#define PR_SET_NAME		15               /* Set process name */
#define MAX_CPUS		4096
#define COMM_LEN		20
#define SYM_LEN			129
#define MAX_PID			65536

#ifndef ALIGN
#define ALIGN(x, a)     (((x) + (a) - 1) & ~((a) - 1))
#endif

#define mb()			asm volatile ("" : : : "memory")

struct sched_atom;

struct task_desc {
	unsigned long		nr;
	unsigned long		pid;
	char			comm[COMM_LEN];

	unsigned long		nr_events;
	unsigned long		curr_event;
	struct sched_atom	**atoms;

	pthread_t		thread;
	sem_t			sleep_sem;

	sem_t			ready_for_work;
	sem_t			work_done_sem;

	u64			cpu_usage;

	u64			task_state;

	unsigned int		exited : 1;		/* exited */
	unsigned int		selected : 1;		/* part of playback */
};

enum sched_event_type {
	SCHED_EVENT_RUN,
	SCHED_EVENT_SLEEP,
	SCHED_EVENT_WAKEUP,
	SCHED_EVENT_MIGRATION,
	SCHED_EVENT_EXIT,
	SCHED_EVENT_FORK_PARENT,
	SCHED_EVENT_FORK_CHILD,
};

struct sched_atom {
	enum sched_event_type	type;
	int			specific_wait;
	u64			timestamp;
	u64			duration;
	unsigned long		nr;
	sem_t			*wait_sem;
	struct task_desc	*wakee;
	struct sched_atom	*wakee_event;
	u64			task_state;
	int			pid;
	struct task_desc	*parent;
	struct task_desc	*child;

	/* extra */
	unsigned int		exited;	/* event was generated after task has called exit() */
	char 			*msg;

	unsigned int		waker_count;
	struct task_desc	**wakers;
	struct sched_atom	**waker_events;
	unsigned long		wake_id;
};

#define TASK_STATE_TO_CHAR_STR "RSDTtZX"

enum thread_state {
	THREAD_SLEEPING = 0,
	THREAD_WAIT_CPU,
	THREAD_SCHED_IN,
	THREAD_IGNORE
};

struct work_atom {
	struct list_head	list;
	enum thread_state	state;
	u64			sched_out_time;
	u64			wake_up_time;
	u64			sched_in_time;
	u64			runtime;
};

struct work_atoms {
	struct list_head	work_list;
	struct thread		*thread;
	struct rb_node		node;
	u64			max_lat;
	u64			max_lat_at;
	u64			total_lat;
	u64			nb_atoms;
	u64			total_runtime;
};

typedef int (*sort_fn_t)(struct work_atoms *, struct work_atoms *);

struct perf_sched;

static const char *sched_atom_str(struct perf_sched *sched,
		const struct sched_atom *atom);

struct trace_sched_handler {
	int (*switch_event)(struct perf_sched *sched, struct perf_evsel *evsel,
			    struct perf_sample *sample, struct machine *machine);

	int (*runtime_event)(struct perf_sched *sched, struct perf_evsel *evsel,
			     struct perf_sample *sample, struct machine *machine);

	int (*wakeup_event)(struct perf_sched *sched, struct perf_evsel *evsel,
			    struct perf_sample *sample, struct machine *machine);

	int (*fork_event)(struct perf_sched *sched, struct perf_evsel *evsel,
			  struct perf_sample *sample);

	int (*migrate_task_event)(struct perf_sched *sched,
				  struct perf_evsel *evsel,
				  struct perf_sample *sample,
				  struct machine *machine);

	int (*exit_event)(struct perf_sched *sched,
				  struct perf_evsel *evsel,
				  struct perf_sample *sample,
				  struct machine *machine);

};

struct select_list_entry {
	struct list_head node;
	int pid;
	char *name;
};

struct analyze_data {
	u64	capture_start;
	u64	capture_end;
	u64	runtime;
	u64	vruntime;
};

struct perf_sched {
	struct perf_tool tool;
	const char	 *input_name;
	const char	 *sort_order;
	unsigned long	 nr_tasks;
	struct task_desc *pid_to_task[MAX_PID];
	struct task_desc **tasks;
	const struct trace_sched_handler *tp_handler;
	pthread_mutex_t	 start_work_mutex;
	pthread_mutex_t	 work_done_wait_mutex;
	int		 profile_cpu;
/*
 * Track the current task - that way we can know whether there's any
 * weird events, such as a task being switched away that is not current.
 */
	int		 max_cpu;
	u32		 curr_pid[MAX_CPUS];
	struct thread	 *curr_thread[MAX_CPUS];
	char		 next_shortname1;
	char		 next_shortname2;
	unsigned int	 replay_repeat;
	unsigned long	 nr_run_events;
	unsigned long	 nr_sleep_events;
	unsigned long	 nr_wakeup_events;
	unsigned long	 nr_sleep_corrections;
	unsigned long	 nr_run_events_optimized;
	unsigned long	 targetless_wakeups;
	unsigned long	 multitarget_wakeups;
	unsigned long	 nr_runs;
	unsigned long	 nr_timestamps;
	unsigned long	 nr_unordered_timestamps;
	unsigned long	 nr_state_machine_bugs;
	unsigned long	 nr_context_switch_bugs;
	unsigned long	 nr_events;
	unsigned long	 nr_lost_chunks;
	unsigned long	 nr_lost_events;
	u64		 run_measurement_overhead;
	u64		 sleep_measurement_overhead;
	u64		 start_time;
	u64		 cpu_usage;
	u64		 runavg_cpu_usage;
	u64		 parent_cpu_usage;
	u64		 runavg_parent_cpu_usage;
	u64		 sum_runtime;
	u64		 sum_fluct;
	u64		 run_avg;
	u64		 all_runtime;
	u64		 all_count;
	u64		 cpu_last_switched[MAX_CPUS];
	struct task_desc *cpu_last_task[MAX_CPUS];
	struct rb_root	 atom_root, sorted_atom_root;
	struct list_head sort_list, cmp_pid;

	u64		bogoloops;

	u64		replay_start_time;
	u64		replay_end_time;
	unsigned long	next_wake_id;
	bool		preserve_time;
	bool		dry_run;
	bool		generate;
	int 		debug;
	bool		spr_list;
	const char	*spr_filename;
	bool		bogoburn;
	bool		spr_replay;

	unsigned long	nr_exit_events;
	unsigned long	nr_fork_parent_events;
	unsigned long	nr_fork_child_events;

	struct playback *playback;

	struct list_head select_list;

	int analyze_maxcpu;
	struct analyze_data *analyze;
};

static u64 get_nsecs(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void burn_nsecs(struct perf_sched *sched, u64 nsecs)
{
	u64 T0 = get_nsecs(), T1;

	do {
		T1 = get_nsecs();
	} while (T1 + sched->run_measurement_overhead < T0 + nsecs);
}

static void sleep_nsecs(u64 nsecs)
{
	struct timespec ts;

	ts.tv_nsec = nsecs % 999999999;
	ts.tv_sec = nsecs / 999999999;

	nanosleep(&ts, NULL);
}

static void calibrate_run_measurement_overhead(struct perf_sched *sched)
{
	u64 T0, T1, delta, min_delta = 1000000000ULL;
	int i;

	for (i = 0; i < 10; i++) {
		T0 = get_nsecs();
		burn_nsecs(sched, 0);
		T1 = get_nsecs();
		delta = T1-T0;
		min_delta = min(min_delta, delta);
	}
	sched->run_measurement_overhead = min_delta;

	printf("run measurement overhead: %" PRIu64 " nsecs\n", min_delta);
}

static void calibrate_sleep_measurement_overhead(struct perf_sched *sched)
{
	u64 T0, T1, delta, min_delta = 1000000000ULL;
	int i;

	for (i = 0; i < 10; i++) {
		T0 = get_nsecs();
		sleep_nsecs(10000);
		T1 = get_nsecs();
		delta = T1-T0;
		min_delta = min(min_delta, delta);
	}
	min_delta -= 10000;
	sched->sleep_measurement_overhead = min_delta;

	printf("sleep measurement overhead: %" PRIu64 " nsecs\n", min_delta);
}

static u64 bogoloops_measure_single(struct perf_sched *sched __maybe_unused,
		u64 loops)
{
	u64 cnt;
	u64 ns1, ns2;

	/* loop to make sure you start close to the monotonic clock */
	ns2 = get_nsecs();
	while ((ns1 = get_nsecs()) - ns2 == 0)
		;
	cnt = loops;
	while (cnt-- > 0)
		mb();
	ns2 = get_nsecs();
	return ns2 - ns1;
}

static u64 bogoloops_measure_stable(struct perf_sched *sched, u64 loops)
{
	int i;
	unsigned int j, k;
	u64 delta;
	u64 delta_samples[16];		/* 16 is an adequate number */
	u64 estimate, maxdiff, new_estimate;
	int imin, imax;	/* indices of min & max */

	i = 0;
	do {
		imin = 0;
		imax = 0;
		estimate = 0;
		for (j = 0; j < ARRAY_SIZE(delta_samples); j++) {
			/* measure a single time */
			delta = bogoloops_measure_single(sched, loops);
			delta_samples[j] = delta;
			if (delta < delta_samples[imin])
				imin = j;
			if (delta > delta_samples[imax])
				imax = j;
			estimate += delta;
		}
		estimate /= ARRAY_SIZE(delta_samples);

		maxdiff = estimate >> 3;	/* maxdiff is 12.5% of estimate */

		/* only keep the ones that are with the proper range */
		k = 0;
		new_estimate = 0;
		for (j = 0; j < ARRAY_SIZE(delta_samples); j++) {
			if (delta_samples[j] > estimate)
				delta = delta_samples[j] - estimate;
			else
				delta = estimate - delta_samples[j];

			/* too bad, continue */
			if (delta > maxdiff)
				continue;
			k++;
			new_estimate += delta_samples[j];
		}

		/* we need at least half the samples to be right */
		if (k >= ARRAY_SIZE(delta_samples) / 2)
			return new_estimate / k;

	} while (i++ < 8);	/* try for 8 times */

	/* we have failed to find a stable measurement */
	/* (this is normal for low loops values) */
	return 0;
}

static void calculate_bogoloops_value(struct perf_sched *sched)
{
	u64 loops, last_loops, new_loops;
	u64 sample_period;
	u64 ns1, ns2, delta, delta_new, delta_diff;

	/* 1 ms */
	sample_period = 1000000;

	ns1 = get_nsecs();
	loops = 0;
	while (((ns2 = get_nsecs()) - ns1) < sample_period)
		loops++;

	/* it is guaranteed that the loops value would be lower */
	/* we grow until we get right after the sample period */
	/* then we interpolate for the period */
	do {
		last_loops = loops;
		delta = bogoloops_measure_stable(sched, loops);
		loops *= 2;
	} while (delta < sample_period);

	new_loops = ((last_loops * sample_period) + (delta / 2)) / delta;
	delta_new = bogoloops_measure_stable(sched, new_loops);

	if (delta_new > sample_period)
		delta_diff = delta_new - sample_period;
	else
		delta_diff = sample_period - delta_new;

	sched->bogoloops = new_loops;
}

static void bogoburn_nsecs(struct perf_sched *sched, u64 nsecs)
{
	u64 cnt;

	cnt = (sched->bogoloops * nsecs) / 1000000LLU;
	while (cnt-- > 0)
		mb();
}

static struct sched_atom *
get_new_event(struct perf_sched *sched __maybe_unused, struct task_desc *task, u64 timestamp)
{
	struct sched_atom *event = zalloc(sizeof(*event));
	unsigned long idx = task->nr_events;
	size_t size;

	event->timestamp = timestamp;
	event->nr = idx;

	event->exited = task->exited;

	task->nr_events++;
	size = sizeof(struct sched_atom *) * task->nr_events;
	task->atoms = realloc(task->atoms, size);
	BUG_ON(!task->atoms);

	task->atoms[idx] = event;

	return event;
}

static struct sched_atom *last_event(struct perf_sched *sched __maybe_unused, struct task_desc *task)
{
	if (!task->nr_events)
		return NULL;

	return task->atoms[task->nr_events - 1];
}

static void add_sched_event_run(struct perf_sched *sched, struct task_desc *task,
				u64 timestamp, u64 duration)
{
	struct sched_atom *event, *curr_event = last_event(sched, task);

	/*
	 * optimize an existing RUN event by merging this one
	 * to it:
	 */
	if (curr_event && curr_event->type == SCHED_EVENT_RUN) {
		sched->nr_run_events_optimized++;
		curr_event->duration += duration;
		return;
	}

	event = get_new_event(sched, task, timestamp);

	event->type = SCHED_EVENT_RUN;
	event->duration = duration;

	sched->nr_run_events++;
}

static void
add_sched_event_exit(struct perf_sched *sched,
		struct task_desc *task, u64 timestamp)
{
	struct sched_atom *event;

	event = get_new_event(sched, task, timestamp);

	event->type = SCHED_EVENT_EXIT;

	sched->nr_exit_events++;
}

static int add_sched_event_wakeup(struct perf_sched *sched, struct task_desc *task,
				   u64 timestamp, struct task_desc *wakee)
{
	struct sched_atom *event, *wakee_event;

	event = get_new_event(sched, task, timestamp);
	event->type = SCHED_EVENT_WAKEUP;
	event->wakee = wakee;

	wakee_event = last_event(sched, wakee);
	if (!wakee_event || wakee_event->type != SCHED_EVENT_SLEEP) {
		sched->targetless_wakeups++;
		return 1;	/* targetless wakeup */
	}

	event->wakee_event = wakee_event;

	/* add to the waker array */
	wakee_event->waker_count++;
	wakee_event->wakers = realloc(wakee_event->wakers,
			wakee_event->waker_count * sizeof(*wakee_event->wakers));
	BUG_ON(wakee_event->wakers == NULL);
	wakee_event->wakers[wakee_event->waker_count-1] = task;

	/* add to the waker event array */
	wakee_event->waker_events = realloc(wakee_event->waker_events,
			wakee_event->waker_count * sizeof(*wakee_event->waker_events));
	BUG_ON(wakee_event->waker_events == NULL);
	wakee_event->waker_events[wakee_event->waker_count-1] = event;


	if (wakee_event->wait_sem) {
		sched->multitarget_wakeups++;
		return 2;	/* multi target wakup */
	}

	wakee_event->wait_sem = zalloc(sizeof(*wakee_event->wait_sem));
	sem_init(wakee_event->wait_sem, 0, 0);
	wakee_event->specific_wait = 1;
	event->wait_sem = wakee_event->wait_sem;

	sched->nr_wakeup_events++;


	return 0;		/* normal wakeup with both waker & wakee */
}

static void add_sched_event_sleep(struct perf_sched *sched, struct task_desc *task,
				  u64 timestamp, u64 task_state __maybe_unused)
{
	struct sched_atom *event = get_new_event(sched, task, timestamp);

	event->type = SCHED_EVENT_SLEEP;

	event->task_state = task_state;

	event->wake_id = ++sched->next_wake_id;
	BUG_ON(sched->next_wake_id == 0);	/* do not allow overflow */

	sched->nr_sleep_events++;
}

static void
add_sched_event_fork_parent(struct perf_sched *sched,
		struct task_desc *task, u64 timestamp, int child_pid)
{
	struct sched_atom *event;

	event = get_new_event(sched, task, timestamp);

	event->type = SCHED_EVENT_FORK_PARENT;
	event->pid = child_pid;

	sched->nr_fork_parent_events++;
}

static void
add_sched_event_fork_child(struct perf_sched *sched,
		struct task_desc *task, u64 timestamp, int parent_pid)
{
	struct sched_atom *event;

	event = get_new_event(sched, task, timestamp);

	event->type = SCHED_EVENT_FORK_CHILD;
	event->pid = parent_pid;

	sched->nr_fork_child_events++;
}

static struct task_desc *register_pid(struct perf_sched *sched,
				      unsigned long pid, const char *comm)
{
	struct task_desc *task;

	BUG_ON(pid >= MAX_PID);

	task = sched->pid_to_task[pid];

	if (task) {
		/* update task name */
		if (strcmp(task->comm, comm) != 0) {
			if (verbose)
				printf("task #%lu with pid %ld updates name from '%s' to '%s'\n",
						task->nr, task->pid, task->comm, comm);
			strcpy(task->comm, comm);
		}
		return task;
	}

	task = zalloc(sizeof(*task));
	task->pid = pid;
	task->nr = sched->nr_tasks;
	strcpy(task->comm, comm);
	/*
	 * every task starts in sleeping state - this gets ignored
	 * if there's no wakeup pointing to this sleep state:
	 * NOTE: spr-replay get's awfully messy with this; removed.
	 */
	if (!sched->spr_replay)
		add_sched_event_sleep(sched, task, 0, 0);

	sched->pid_to_task[pid] = task;
	sched->nr_tasks++;
	sched->tasks = realloc(sched->tasks, sched->nr_tasks * sizeof(struct task_task *));
	BUG_ON(!sched->tasks);
	sched->tasks[task->nr] = task;

	if (verbose)
		printf("registered task #%ld, PID %ld (%s)\n", sched->nr_tasks, pid, comm);

	return task;
}


static void print_task_traces(struct perf_sched *sched)
{
	struct task_desc *task;
	unsigned long i;

	for (i = 0; i < sched->nr_tasks; i++) {
		task = sched->tasks[i];
		printf("task %6ld (%20s:%10ld), nr_events: %ld\n",
			task->nr, task->comm, task->pid, task->nr_events);
	}
}

static void add_cross_task_wakeups(struct perf_sched *sched)
{
	struct task_desc *task1, *task2;
	unsigned long i, j;

	for (i = 0; i < sched->nr_tasks; i++) {
		task1 = sched->tasks[i];
		j = i + 1;
		if (j == sched->nr_tasks)
			j = 0;
		task2 = sched->tasks[j];
		add_sched_event_wakeup(sched, task1, 0, task2);
	}
}

static void perf_sched__process_event(struct perf_sched *sched,
				      struct sched_atom *atom)
{
	int ret = 0;

	switch (atom->type) {
		case SCHED_EVENT_RUN:
			burn_nsecs(sched, atom->duration);
			break;
		case SCHED_EVENT_SLEEP:
			if (atom->wait_sem)
				ret = sem_wait(atom->wait_sem);
			BUG_ON(ret);
			break;
		case SCHED_EVENT_WAKEUP:
			if (atom->wait_sem)
				ret = sem_post(atom->wait_sem);
			BUG_ON(ret);
			break;
		case SCHED_EVENT_MIGRATION:
			break;
			/* unused */
		case SCHED_EVENT_EXIT:
		case SCHED_EVENT_FORK_PARENT:
		case SCHED_EVENT_FORK_CHILD:
			break;
		default:
			BUG_ON(1);
	}
}

static u64 get_cpu_usage_nsec_parent(void)
{
	struct rusage ru;
	u64 sum;
	int err;

	err = getrusage(RUSAGE_SELF, &ru);
	BUG_ON(err);

	sum =  ru.ru_utime.tv_sec*1e9 + ru.ru_utime.tv_usec*1e3;
	sum += ru.ru_stime.tv_sec*1e9 + ru.ru_stime.tv_usec*1e3;

	return sum;
}

static int self_open_counters(void)
{
	struct perf_event_attr attr;
	int fd;

	memset(&attr, 0, sizeof(attr));

	attr.type = PERF_TYPE_SOFTWARE;
	attr.config = PERF_COUNT_SW_TASK_CLOCK;

	fd = sys_perf_event_open(&attr, 0, -1, -1, 0);

	if (fd < 0)
		pr_err("Error: sys_perf_event_open() syscall returned "
		       "with %d (%s)\n", fd, strerror(errno));
	return fd;
}

static u64 get_cpu_usage_nsec_self(int fd)
{
	u64 runtime;
	int ret;

	ret = read(fd, &runtime, sizeof(runtime));
	BUG_ON(ret != sizeof(runtime));

	return runtime;
}

struct sched_thread_parms {
	struct task_desc  *task;
	struct perf_sched *sched;
};

static void *thread_func(void *ctx)
{
	struct sched_thread_parms *parms = ctx;
	struct task_desc *this_task = parms->task;
	struct perf_sched *sched = parms->sched;
	u64 cpu_usage_0, cpu_usage_1;
	unsigned long i, ret;
	char comm2[22];
	int fd;

	free(parms);

	sprintf(comm2, ":%s", this_task->comm);
	prctl(PR_SET_NAME, comm2);
	fd = self_open_counters();
	if (fd < 0)
		return NULL;
again:
	ret = sem_post(&this_task->ready_for_work);
	BUG_ON(ret);
	ret = pthread_mutex_lock(&sched->start_work_mutex);
	BUG_ON(ret);
	ret = pthread_mutex_unlock(&sched->start_work_mutex);
	BUG_ON(ret);

	cpu_usage_0 = get_cpu_usage_nsec_self(fd);

	for (i = 0; i < this_task->nr_events; i++) {
		this_task->curr_event = i;
		perf_sched__process_event(sched, this_task->atoms[i]);
	}

	cpu_usage_1 = get_cpu_usage_nsec_self(fd);
	this_task->cpu_usage = cpu_usage_1 - cpu_usage_0;
	ret = sem_post(&this_task->work_done_sem);
	BUG_ON(ret);

	ret = pthread_mutex_lock(&sched->work_done_wait_mutex);
	BUG_ON(ret);
	ret = pthread_mutex_unlock(&sched->work_done_wait_mutex);
	BUG_ON(ret);

	goto again;
}

static void create_tasks(struct perf_sched *sched)
{
	struct task_desc *task;
	pthread_attr_t attr;
	unsigned long i;
	int err;

	err = pthread_attr_init(&attr);
	BUG_ON(err);
	err = pthread_attr_setstacksize(&attr,
			(size_t) max(16 * 1024, PTHREAD_STACK_MIN));
	BUG_ON(err);
	err = pthread_mutex_lock(&sched->start_work_mutex);
	BUG_ON(err);
	err = pthread_mutex_lock(&sched->work_done_wait_mutex);
	BUG_ON(err);
	for (i = 0; i < sched->nr_tasks; i++) {
		struct sched_thread_parms *parms = malloc(sizeof(*parms));
		BUG_ON(parms == NULL);
		parms->task = task = sched->tasks[i];
		parms->sched = sched;
		sem_init(&task->sleep_sem, 0, 0);
		sem_init(&task->ready_for_work, 0, 0);
		sem_init(&task->work_done_sem, 0, 0);
		task->curr_event = 0;
		err = pthread_create(&task->thread, &attr, thread_func, parms);
		BUG_ON(err);
	}
}

static void wait_for_tasks(struct perf_sched *sched)
{
	u64 cpu_usage_0, cpu_usage_1;
	struct task_desc *task;
	unsigned long i, ret;

	sched->start_time = get_nsecs();
	sched->cpu_usage = 0;
	pthread_mutex_unlock(&sched->work_done_wait_mutex);

	for (i = 0; i < sched->nr_tasks; i++) {
		task = sched->tasks[i];
		ret = sem_wait(&task->ready_for_work);
		BUG_ON(ret);
		sem_init(&task->ready_for_work, 0, 0);
	}
	ret = pthread_mutex_lock(&sched->work_done_wait_mutex);
	BUG_ON(ret);

	cpu_usage_0 = get_cpu_usage_nsec_parent();

	pthread_mutex_unlock(&sched->start_work_mutex);

	for (i = 0; i < sched->nr_tasks; i++) {
		task = sched->tasks[i];
		ret = sem_wait(&task->work_done_sem);
		BUG_ON(ret);
		sem_init(&task->work_done_sem, 0, 0);
		sched->cpu_usage += task->cpu_usage;
		task->cpu_usage = 0;
	}

	cpu_usage_1 = get_cpu_usage_nsec_parent();
	if (!sched->runavg_cpu_usage)
		sched->runavg_cpu_usage = sched->cpu_usage;
	sched->runavg_cpu_usage = (sched->runavg_cpu_usage * 9 + sched->cpu_usage) / 10;

	sched->parent_cpu_usage = cpu_usage_1 - cpu_usage_0;
	if (!sched->runavg_parent_cpu_usage)
		sched->runavg_parent_cpu_usage = sched->parent_cpu_usage;
	sched->runavg_parent_cpu_usage = (sched->runavg_parent_cpu_usage * 9 +
					 sched->parent_cpu_usage)/10;

	ret = pthread_mutex_lock(&sched->start_work_mutex);
	BUG_ON(ret);

	for (i = 0; i < sched->nr_tasks; i++) {
		task = sched->tasks[i];
		sem_init(&task->sleep_sem, 0, 0);
		task->curr_event = 0;
	}
}

static void run_one_test(struct perf_sched *sched)
{
	u64 T0, T1, delta, avg_delta, fluct;

	T0 = get_nsecs();
	wait_for_tasks(sched);
	T1 = get_nsecs();

	delta = T1 - T0;
	sched->sum_runtime += delta;
	sched->nr_runs++;

	avg_delta = sched->sum_runtime / sched->nr_runs;
	if (delta < avg_delta)
		fluct = avg_delta - delta;
	else
		fluct = delta - avg_delta;
	sched->sum_fluct += fluct;
	if (!sched->run_avg)
		sched->run_avg = delta;
	sched->run_avg = (sched->run_avg * 9 + delta) / 10;

	printf("#%-3ld: %0.3f, ", sched->nr_runs, (double)delta / 1000000.0);

	printf("ravg: %0.2f, ", (double)sched->run_avg / 1e6);

	printf("cpu: %0.2f / %0.2f",
		(double)sched->cpu_usage / 1e6, (double)sched->runavg_cpu_usage / 1e6);

#if 0
	/*
	 * rusage statistics done by the parent, these are less
	 * accurate than the sched->sum_exec_runtime based statistics:
	 */
	printf(" [%0.2f / %0.2f]",
		(double)sched->parent_cpu_usage/1e6,
		(double)sched->runavg_parent_cpu_usage/1e6);
#endif

	printf("\n");

	if (sched->nr_sleep_corrections)
		printf(" (%ld sleep corrections)\n", sched->nr_sleep_corrections);
	sched->nr_sleep_corrections = 0;
}

static void test_calibrations(struct perf_sched *sched)
{
	u64 T0, T1;

	T0 = get_nsecs();
	burn_nsecs(sched, 1e6);
	T1 = get_nsecs();

	printf("the run test took %" PRIu64 " nsecs\n", T1 - T0);

	T0 = get_nsecs();
	sleep_nsecs(1e6);
	T1 = get_nsecs();

	printf("the sleep test took %" PRIu64 " nsecs\n", T1 - T0);
}

static int
replay_wakeup_event(struct perf_sched *sched,
		    struct perf_evsel *evsel, struct perf_sample *sample,
		    struct machine *machine __maybe_unused)
{
	const char *comm = perf_evsel__strval(evsel, sample, "comm");
	const u32 pid	 = perf_evsel__intval(evsel, sample, "pid");
	struct task_desc *waker, *wakee;
	struct sched_atom *waker_event, *wakee_event;
	char *s, *e;
	char buf[BUFSIZ];
	int ret;

	if (verbose) {
		printf("sched_wakeup event %p\n", evsel);

		printf(" ... pid %d woke up %s/%d\n", sample->tid, comm, pid);
	}

	waker = register_pid(sched, sample->tid, "<unknown>");
	wakee = register_pid(sched, pid, comm);

	ret = add_sched_event_wakeup(sched, waker, sample->time, wakee);

	waker_event = last_event(sched, waker);
	BUG_ON(waker_event == NULL);

	wakee_event = last_event(sched, wakee);

	if (sched->debug > 2) {
		s = buf;
		e = &buf[ARRAY_SIZE(buf)];
		e[-1] = '\0';

		snprintf(s, e - s, "wakee %u",
				pid);
		e[-1] = '\0';
		s += strlen(s);

		if (ret == 1) {
			snprintf(s, e - s, " (targetless )");
			e[-1] = '\0';
			s += strlen(s);
		} else if (ret == 2) {
			snprintf(s, e - s, " (multitarget)");
			e[-1] = '\0';
			s += strlen(s);
		}

		if (wakee_event != NULL) {
			snprintf(s, e - s, " (%s)",
					sched_atom_str(sched, wakee_event));
			e[-1] = '\0';
			s += strlen(s);
		}

		waker_event->msg = strdup(buf);
	}

	return 0;
}

static int replay_switch_event(struct perf_sched *sched,
			       struct perf_evsel *evsel,
			       struct perf_sample *sample,
			       struct machine *machine __maybe_unused)
{
	const char *prev_comm  = perf_evsel__strval(evsel, sample, "prev_comm"),
		   *next_comm  = perf_evsel__strval(evsel, sample, "next_comm");
	const u32 prev_pid = perf_evsel__intval(evsel, sample, "prev_pid"),
		  next_pid = perf_evsel__intval(evsel, sample, "next_pid");
	const u64 prev_state = perf_evsel__intval(evsel, sample, "prev_state");
	struct task_desc *prev, *next;
	struct sched_atom *prev_atom;
	u64 timestamp0, timestamp = sample->time;
	int cpu = sample->cpu;
	s64 delta;
	char buf[BUFSIZ];

	if (verbose)
		printf("sched_switch event %p\n", evsel);

	if (cpu >= MAX_CPUS || cpu < 0)
		return 0;

	timestamp0 = sched->cpu_last_switched[cpu];
	if (timestamp0)
		delta = timestamp - timestamp0;
	else
		delta = 0;

	if (delta < 0) {
		pr_err("hm, delta: %" PRIu64 " < 0 ?\n", delta);
		return -1;
	}

	pr_debug(" ... switch from %s/%d to %s/%d [ran %" PRIu64 " nsecs]\n",
		 prev_comm, prev_pid, next_comm, next_pid, delta);

	prev = register_pid(sched, prev_pid, prev_comm);
	next = register_pid(sched, next_pid, next_comm);

	sched->cpu_last_task[cpu] = next;
	sched->cpu_last_switched[cpu] = timestamp;

	add_sched_event_run(sched, prev, timestamp, delta);
	add_sched_event_sleep(sched, prev, timestamp, prev_state);

	prev->task_state = prev_state;
	next->task_state = 0;	/* task running */

	prev_atom = last_event(sched, prev);
	BUG_ON(prev_atom == NULL);

	if (sched->debug > 2) {
		snprintf(buf, sizeof(buf), "switch to %d", next_pid);
		prev_atom->msg = strdup(buf);
	}

	return 0;
}

static int replay_fork_event(struct perf_sched *sched, struct perf_evsel *evsel,
			     struct perf_sample *sample)
{
	const char *parent_comm = perf_evsel__strval(evsel, sample, "parent_comm"),
		   *child_comm  = perf_evsel__strval(evsel, sample, "child_comm");
	const u32 parent_pid  = perf_evsel__intval(evsel, sample, "parent_pid"),
		  child_pid  = perf_evsel__intval(evsel, sample, "child_pid");
	u64 timestamp = sample->time;
	struct task_desc *parent, *child;
	struct sched_atom *atom;
	char buf[BUFSIZ];

	if (verbose) {
		printf("sched_fork event %p\n", evsel);
		printf("... parent: %s/%d\n", parent_comm, parent_pid);
		printf("...  child: %s/%d\n", child_comm, child_pid);
	}

	parent = register_pid(sched, parent_pid, parent_comm);
	child = register_pid(sched, child_pid, child_comm);

	add_sched_event_fork_parent(sched, parent, timestamp, child_pid);

	atom = last_event(sched, parent);
	BUG_ON(atom == NULL);
	atom->child = child;

	if (sched->debug > 2) {
		snprintf(buf, sizeof(buf), "child %d", child_pid);
		atom->msg = strdup(buf);
	}

	add_sched_event_fork_child(sched, child, timestamp, parent_pid);

	atom = last_event(sched, child);
	BUG_ON(atom == NULL);
	atom->parent = parent;

	if (sched->debug > 2) {
		snprintf(buf, sizeof(buf), "parent %d", parent_pid);
		atom->msg = strdup(buf);
	}
	return 0;
}

static int replay_exit_event(struct perf_sched *sched, struct perf_evsel *evsel,
			     struct perf_sample *sample,
			     struct machine *machine __maybe_unused)
{
	struct task_desc *task;
	const u32 pid = perf_evsel__intval(evsel, sample, "pid");
	u64 timestamp = sample->time;

	task = register_pid(sched, pid, "<unknown>");	/* should never pick up unkown */
	add_sched_event_exit(sched, task, timestamp);
	task->exited = 1;	/* mark that this task has exited */

	return 0;
}

struct sort_dimension {
	const char		*name;
	sort_fn_t		cmp;
	struct list_head	list;
};

static int
thread_lat_cmp(struct list_head *list, struct work_atoms *l, struct work_atoms *r)
{
	struct sort_dimension *sort;
	int ret = 0;

	BUG_ON(list_empty(list));

	list_for_each_entry(sort, list, list) {
		ret = sort->cmp(l, r);
		if (ret)
			return ret;
	}

	return ret;
}

static struct work_atoms *
thread_atoms_search(struct rb_root *root, struct thread *thread,
			 struct list_head *sort_list)
{
	struct rb_node *node = root->rb_node;
	struct work_atoms key = { .thread = thread };

	while (node) {
		struct work_atoms *atoms;
		int cmp;

		atoms = container_of(node, struct work_atoms, node);

		cmp = thread_lat_cmp(sort_list, &key, atoms);
		if (cmp > 0)
			node = node->rb_left;
		else if (cmp < 0)
			node = node->rb_right;
		else {
			BUG_ON(thread != atoms->thread);
			return atoms;
		}
	}
	return NULL;
}

static void
__thread_latency_insert(struct rb_root *root, struct work_atoms *data,
			 struct list_head *sort_list)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	while (*new) {
		struct work_atoms *this;
		int cmp;

		this = container_of(*new, struct work_atoms, node);
		parent = *new;

		cmp = thread_lat_cmp(sort_list, data, this);

		if (cmp > 0)
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);
}

static int thread_atoms_insert(struct perf_sched *sched, struct thread *thread)
{
	struct work_atoms *atoms = zalloc(sizeof(*atoms));
	if (!atoms) {
		pr_err("No memory at %s\n", __func__);
		return -1;
	}

	atoms->thread = thread;
	INIT_LIST_HEAD(&atoms->work_list);
	__thread_latency_insert(&sched->atom_root, atoms, &sched->cmp_pid);
	return 0;
}

static int latency_fork_event(struct perf_sched *sched __maybe_unused,
			      struct perf_evsel *evsel __maybe_unused,
			      struct perf_sample *sample __maybe_unused)
{
	/* should insert the newcomer */
	return 0;
}

static char sched_out_state(u64 prev_state)
{
	const char *str = TASK_STATE_TO_CHAR_STR;

	return str[prev_state];
}

static int
add_sched_out_event(struct work_atoms *atoms,
		    char run_state,
		    u64 timestamp)
{
	struct work_atom *atom = zalloc(sizeof(*atom));
	if (!atom) {
		pr_err("Non memory at %s", __func__);
		return -1;
	}

	atom->sched_out_time = timestamp;

	if (run_state == 'R') {
		atom->state = THREAD_WAIT_CPU;
		atom->wake_up_time = atom->sched_out_time;
	}

	list_add_tail(&atom->list, &atoms->work_list);
	return 0;
}

static void
add_runtime_event(struct work_atoms *atoms, u64 delta,
		  u64 timestamp __maybe_unused)
{
	struct work_atom *atom;

	BUG_ON(list_empty(&atoms->work_list));

	atom = list_entry(atoms->work_list.prev, struct work_atom, list);

	atom->runtime += delta;
	atoms->total_runtime += delta;
}

static void
add_sched_in_event(struct work_atoms *atoms, u64 timestamp)
{
	struct work_atom *atom;
	u64 delta;

	if (list_empty(&atoms->work_list))
		return;

	atom = list_entry(atoms->work_list.prev, struct work_atom, list);

	if (atom->state != THREAD_WAIT_CPU)
		return;

	if (timestamp < atom->wake_up_time) {
		atom->state = THREAD_IGNORE;
		return;
	}

	atom->state = THREAD_SCHED_IN;
	atom->sched_in_time = timestamp;

	delta = atom->sched_in_time - atom->wake_up_time;
	atoms->total_lat += delta;
	if (delta > atoms->max_lat) {
		atoms->max_lat = delta;
		atoms->max_lat_at = timestamp;
	}
	atoms->nb_atoms++;
}

static int analyze_runtime_event(struct perf_sched *sched,
				 struct perf_evsel *evsel,
				 struct perf_sample *sample,
				 struct machine *machine)
{
	const u32 pid	   = perf_evsel__intval(evsel, sample, "pid");
	const u64 runtime  = perf_evsel__intval(evsel, sample, "runtime");
	const u64 vruntime  = perf_evsel__intval(evsel, sample, "vruntime");
	struct thread *thread = machine__findnew_thread(machine, pid);
	u64 timestamp = sample->time;
	int cpu = sample->cpu;
	struct analyze_data *ad;

	BUG_ON(cpu >= MAX_CPUS || cpu < 0);

	BUG_ON(cpu >= sched->analyze_maxcpu);
	BUG_ON(sched->analyze == NULL);

	ad = sched->analyze + cpu;
	if (ad->capture_start == (u64)-1LLU)
		ad->capture_start = timestamp;
	ad->capture_end = timestamp;

	/* ignore the idle thread */
	if (strcmp(thread->comm, "swapper") == 0)
		return 0;

	ad->runtime += runtime;
	ad->vruntime += vruntime;

	return 0;
}

static int latency_switch_event(struct perf_sched *sched,
				struct perf_evsel *evsel,
				struct perf_sample *sample,
				struct machine *machine)
{
	const u32 prev_pid = perf_evsel__intval(evsel, sample, "prev_pid"),
		  next_pid = perf_evsel__intval(evsel, sample, "next_pid");
	const u64 prev_state = perf_evsel__intval(evsel, sample, "prev_state");
	struct work_atoms *out_events, *in_events;
	struct thread *sched_out, *sched_in;
	u64 timestamp0, timestamp = sample->time;
	int cpu = sample->cpu;
	s64 delta;

	BUG_ON(cpu >= MAX_CPUS || cpu < 0);

	timestamp0 = sched->cpu_last_switched[cpu];
	sched->cpu_last_switched[cpu] = timestamp;
	if (timestamp0)
		delta = timestamp - timestamp0;
	else
		delta = 0;

	if (delta < 0) {
		pr_err("hm, delta: %" PRIu64 " < 0 ?\n", delta);
		return -1;
	}

	sched_out = machine__findnew_thread(machine, prev_pid);
	sched_in = machine__findnew_thread(machine, next_pid);

	out_events = thread_atoms_search(&sched->atom_root, sched_out, &sched->cmp_pid);
	if (!out_events) {
		if (thread_atoms_insert(sched, sched_out))
			return -1;
		out_events = thread_atoms_search(&sched->atom_root, sched_out, &sched->cmp_pid);
		if (!out_events) {
			pr_err("out-event: Internal tree error");
			return -1;
		}
	}
	if (add_sched_out_event(out_events, sched_out_state(prev_state), timestamp))
		return -1;

	in_events = thread_atoms_search(&sched->atom_root, sched_in, &sched->cmp_pid);
	if (!in_events) {
		if (thread_atoms_insert(sched, sched_in))
			return -1;
		in_events = thread_atoms_search(&sched->atom_root, sched_in, &sched->cmp_pid);
		if (!in_events) {
			pr_err("in-event: Internal tree error");
			return -1;
		}
		/*
		 * Take came in we have not heard about yet,
		 * add in an initial atom in runnable state:
		 */
		if (add_sched_out_event(in_events, 'R', timestamp))
			return -1;
	}
	add_sched_in_event(in_events, timestamp);

	return 0;
}

static int latency_runtime_event(struct perf_sched *sched,
				 struct perf_evsel *evsel,
				 struct perf_sample *sample,
				 struct machine *machine)
{
	const u32 pid	   = perf_evsel__intval(evsel, sample, "pid");
	const u64 runtime  = perf_evsel__intval(evsel, sample, "runtime");
	struct thread *thread = machine__findnew_thread(machine, pid);
	struct work_atoms *atoms = thread_atoms_search(&sched->atom_root, thread, &sched->cmp_pid);
	u64 timestamp = sample->time;
	int cpu = sample->cpu;

	BUG_ON(cpu >= MAX_CPUS || cpu < 0);
	if (!atoms) {
		if (thread_atoms_insert(sched, thread))
			return -1;
		atoms = thread_atoms_search(&sched->atom_root, thread, &sched->cmp_pid);
		if (!atoms) {
			pr_err("in-event: Internal tree error");
			return -1;
		}
		if (add_sched_out_event(atoms, 'R', timestamp))
			return -1;
	}

	add_runtime_event(atoms, runtime, timestamp);
	return 0;
}

static int latency_wakeup_event(struct perf_sched *sched,
				struct perf_evsel *evsel,
				struct perf_sample *sample,
				struct machine *machine)
{
	const u32 pid	  = perf_evsel__intval(evsel, sample, "pid"),
		  success = perf_evsel__intval(evsel, sample, "success");
	struct work_atoms *atoms;
	struct work_atom *atom;
	struct thread *wakee;
	u64 timestamp = sample->time;

	/* Note for later, it may be interesting to observe the failing cases */
	if (!success)
		return 0;

	wakee = machine__findnew_thread(machine, pid);
	atoms = thread_atoms_search(&sched->atom_root, wakee, &sched->cmp_pid);
	if (!atoms) {
		if (thread_atoms_insert(sched, wakee))
			return -1;
		atoms = thread_atoms_search(&sched->atom_root, wakee, &sched->cmp_pid);
		if (!atoms) {
			pr_err("wakeup-event: Internal tree error");
			return -1;
		}
		if (add_sched_out_event(atoms, 'S', timestamp))
			return -1;
	}

	BUG_ON(list_empty(&atoms->work_list));

	atom = list_entry(atoms->work_list.prev, struct work_atom, list);

	/*
	 * You WILL be missing events if you've recorded only
	 * one CPU, or are only looking at only one, so don't
	 * make useless noise.
	 */
	if (sched->profile_cpu == -1 && atom->state != THREAD_SLEEPING)
		sched->nr_state_machine_bugs++;

	sched->nr_timestamps++;
	if (atom->sched_out_time > timestamp) {
		sched->nr_unordered_timestamps++;
		return 0;
	}

	atom->state = THREAD_WAIT_CPU;
	atom->wake_up_time = timestamp;
	return 0;
}

static int latency_migrate_task_event(struct perf_sched *sched,
				      struct perf_evsel *evsel,
				      struct perf_sample *sample,
				      struct machine *machine)
{
	const u32 pid = perf_evsel__intval(evsel, sample, "pid");
	u64 timestamp = sample->time;
	struct work_atoms *atoms;
	struct work_atom *atom;
	struct thread *migrant;

	/*
	 * Only need to worry about migration when profiling one CPU.
	 */
	if (sched->profile_cpu == -1)
		return 0;

	migrant = machine__findnew_thread(machine, pid);
	atoms = thread_atoms_search(&sched->atom_root, migrant, &sched->cmp_pid);
	if (!atoms) {
		if (thread_atoms_insert(sched, migrant))
			return -1;
		register_pid(sched, migrant->pid, migrant->comm);
		atoms = thread_atoms_search(&sched->atom_root, migrant, &sched->cmp_pid);
		if (!atoms) {
			pr_err("migration-event: Internal tree error");
			return -1;
		}
		if (add_sched_out_event(atoms, 'R', timestamp))
			return -1;
	}

	BUG_ON(list_empty(&atoms->work_list));

	atom = list_entry(atoms->work_list.prev, struct work_atom, list);
	atom->sched_in_time = atom->sched_out_time = atom->wake_up_time = timestamp;

	sched->nr_timestamps++;

	if (atom->sched_out_time > timestamp)
		sched->nr_unordered_timestamps++;

	return 0;
}

static void output_lat_thread(struct perf_sched *sched, struct work_atoms *work_list)
{
	int i;
	int ret;
	u64 avg;

	if (!work_list->nb_atoms)
		return;
	/*
	 * Ignore idle threads:
	 */
	if (!strcmp(work_list->thread->comm, "swapper"))
		return;

	sched->all_runtime += work_list->total_runtime;
	sched->all_count   += work_list->nb_atoms;

	ret = printf("  %s:%d ", work_list->thread->comm, work_list->thread->pid);

	for (i = 0; i < 24 - ret; i++)
		printf(" ");

	avg = work_list->total_lat / work_list->nb_atoms;

	printf("|%11.3f ms |%9" PRIu64 " | avg:%9.3f ms | max:%9.3f ms | max at: %9.6f s\n",
	      (double)work_list->total_runtime / 1e6,
		 work_list->nb_atoms, (double)avg / 1e6,
		 (double)work_list->max_lat / 1e6,
		 (double)work_list->max_lat_at / 1e9);
}

static int pid_cmp(struct work_atoms *l, struct work_atoms *r)
{
	if (l->thread->pid < r->thread->pid)
		return -1;
	if (l->thread->pid > r->thread->pid)
		return 1;

	return 0;
}

static int avg_cmp(struct work_atoms *l, struct work_atoms *r)
{
	u64 avgl, avgr;

	if (!l->nb_atoms)
		return -1;

	if (!r->nb_atoms)
		return 1;

	avgl = l->total_lat / l->nb_atoms;
	avgr = r->total_lat / r->nb_atoms;

	if (avgl < avgr)
		return -1;
	if (avgl > avgr)
		return 1;

	return 0;
}

static int max_cmp(struct work_atoms *l, struct work_atoms *r)
{
	if (l->max_lat < r->max_lat)
		return -1;
	if (l->max_lat > r->max_lat)
		return 1;

	return 0;
}

static int switch_cmp(struct work_atoms *l, struct work_atoms *r)
{
	if (l->nb_atoms < r->nb_atoms)
		return -1;
	if (l->nb_atoms > r->nb_atoms)
		return 1;

	return 0;
}

static int runtime_cmp(struct work_atoms *l, struct work_atoms *r)
{
	if (l->total_runtime < r->total_runtime)
		return -1;
	if (l->total_runtime > r->total_runtime)
		return 1;

	return 0;
}

static int sort_dimension__add(const char *tok, struct list_head *list)
{
	size_t i;
	static struct sort_dimension avg_sort_dimension = {
		.name = "avg",
		.cmp  = avg_cmp,
	};
	static struct sort_dimension max_sort_dimension = {
		.name = "max",
		.cmp  = max_cmp,
	};
	static struct sort_dimension pid_sort_dimension = {
		.name = "pid",
		.cmp  = pid_cmp,
	};
	static struct sort_dimension runtime_sort_dimension = {
		.name = "runtime",
		.cmp  = runtime_cmp,
	};
	static struct sort_dimension switch_sort_dimension = {
		.name = "switch",
		.cmp  = switch_cmp,
	};
	struct sort_dimension *available_sorts[] = {
		&pid_sort_dimension,
		&avg_sort_dimension,
		&max_sort_dimension,
		&switch_sort_dimension,
		&runtime_sort_dimension,
	};

	for (i = 0; i < ARRAY_SIZE(available_sorts); i++) {
		if (!strcmp(available_sorts[i]->name, tok)) {
			list_add_tail(&available_sorts[i]->list, list);

			return 0;
		}
	}

	return -1;
}

static void perf_sched__sort_lat(struct perf_sched *sched)
{
	struct rb_node *node;

	for (;;) {
		struct work_atoms *data;
		node = rb_first(&sched->atom_root);
		if (!node)
			break;

		rb_erase(node, &sched->atom_root);
		data = rb_entry(node, struct work_atoms, node);
		__thread_latency_insert(&sched->sorted_atom_root, data, &sched->sort_list);
	}
}

static int process_sched_wakeup_event(struct perf_tool *tool,
				      struct perf_evsel *evsel,
				      struct perf_sample *sample,
				      struct machine *machine)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);

	if (sched->tp_handler->wakeup_event)
		return sched->tp_handler->wakeup_event(sched, evsel, sample, machine);

	return 0;
}

static int map_switch_event(struct perf_sched *sched, struct perf_evsel *evsel,
			    struct perf_sample *sample, struct machine *machine)
{
	const u32 prev_pid = perf_evsel__intval(evsel, sample, "prev_pid"),
		  next_pid = perf_evsel__intval(evsel, sample, "next_pid");
	struct thread *sched_out __maybe_unused, *sched_in;
	int new_shortname;
	u64 timestamp0, timestamp = sample->time;
	s64 delta;
	int cpu, this_cpu = sample->cpu;

	BUG_ON(this_cpu >= MAX_CPUS || this_cpu < 0);

	if (this_cpu > sched->max_cpu)
		sched->max_cpu = this_cpu;

	timestamp0 = sched->cpu_last_switched[this_cpu];
	sched->cpu_last_switched[this_cpu] = timestamp;
	if (timestamp0)
		delta = timestamp - timestamp0;
	else
		delta = 0;

	if (delta < 0) {
		pr_err("hm, delta: %" PRIu64 " < 0 ?\n", delta);
		return -1;
	}

	sched_out = machine__findnew_thread(machine, prev_pid);
	sched_in = machine__findnew_thread(machine, next_pid);

	sched->curr_thread[this_cpu] = sched_in;

	printf("  ");

	new_shortname = 0;
	if (!sched_in->shortname[0]) {
		sched_in->shortname[0] = sched->next_shortname1;
		sched_in->shortname[1] = sched->next_shortname2;

		if (sched->next_shortname1 < 'Z') {
			sched->next_shortname1++;
		} else {
			sched->next_shortname1='A';
			if (sched->next_shortname2 < '9') {
				sched->next_shortname2++;
			} else {
				sched->next_shortname2='0';
			}
		}
		new_shortname = 1;
	}

	for (cpu = 0; cpu <= sched->max_cpu; cpu++) {
		if (cpu != this_cpu)
			printf(" ");
		else
			printf("*");

		if (sched->curr_thread[cpu]) {
			if (sched->curr_thread[cpu]->pid)
				printf("%2s ", sched->curr_thread[cpu]->shortname);
			else
				printf(".  ");
		} else
			printf("   ");
	}

	printf("  %12.6f secs ", (double)timestamp/1e9);
	if (new_shortname) {
		printf("%s => %s:%d\n",
			sched_in->shortname, sched_in->comm, sched_in->pid);
	} else {
		printf("\n");
	}

	return 0;
}

static int process_sched_switch_event(struct perf_tool *tool,
				      struct perf_evsel *evsel,
				      struct perf_sample *sample,
				      struct machine *machine)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);
	int this_cpu = sample->cpu, err = 0;
	u32 prev_pid = perf_evsel__intval(evsel, sample, "prev_pid"),
	    next_pid = perf_evsel__intval(evsel, sample, "next_pid");

	if (sched->curr_pid[this_cpu] != (u32)-1) {
		/*
		 * Are we trying to switch away a PID that is
		 * not current?
		 */
		if (sched->curr_pid[this_cpu] != prev_pid)
			sched->nr_context_switch_bugs++;
	}

	if (sched->tp_handler->switch_event)
		err = sched->tp_handler->switch_event(sched, evsel, sample, machine);

	sched->curr_pid[this_cpu] = next_pid;
	return err;
}

static int process_sched_runtime_event(struct perf_tool *tool,
				       struct perf_evsel *evsel,
				       struct perf_sample *sample,
				       struct machine *machine)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);

	if (sched->tp_handler->runtime_event)
		return sched->tp_handler->runtime_event(sched, evsel, sample, machine);

	return 0;
}

static int process_sched_fork_event(struct perf_tool *tool,
				    struct perf_evsel *evsel,
				    struct perf_sample *sample,
				    struct machine *machine __maybe_unused)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);

	if (sched->tp_handler->fork_event)
		return sched->tp_handler->fork_event(sched, evsel, sample);

	return 0;
}

static int process_sched_exit_event(struct perf_tool *tool,
				    struct perf_evsel *evsel,
				    struct perf_sample *sample,
				    struct machine *machine)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);

	if (sched->tp_handler->exit_event)
		return sched->tp_handler->exit_event(sched, evsel, sample, machine);

	return 0;
}

static int process_sched_migrate_task_event(struct perf_tool *tool,
					    struct perf_evsel *evsel,
					    struct perf_sample *sample,
					    struct machine *machine)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);

	if (sched->tp_handler->migrate_task_event)
		return sched->tp_handler->migrate_task_event(sched, evsel, sample, machine);

	return 0;
}

typedef int (*tracepoint_handler)(struct perf_tool *tool,
				  struct perf_evsel *evsel,
				  struct perf_sample *sample,
				  struct machine *machine);

static int perf_sched__process_tracepoint_sample(struct perf_tool *tool __maybe_unused,
						 union perf_event *event __maybe_unused,
						 struct perf_sample *sample,
						 struct perf_evsel *evsel,
						 struct machine *machine)
{
	struct thread *thread = machine__findnew_thread(machine, sample->tid);
	int err = 0;

	if (thread == NULL) {
		pr_debug("problem processing %s event, skipping it.\n",
			 perf_evsel__name(evsel));
		return -1;
	}

	evsel->hists.stats.total_period += sample->period;
	hists__inc_nr_events(&evsel->hists, PERF_RECORD_SAMPLE);

	if (evsel->handler.func != NULL) {
		tracepoint_handler f = evsel->handler.func;
		err = f(tool, evsel, sample, machine);
	}

	return err;
}

static int perf_sched__read_events(struct perf_sched *sched, bool destroy,
				   struct perf_session **psession)
{
	const struct perf_evsel_str_handler handlers[] = {
		{ "sched:sched_switch",	      process_sched_switch_event, },
		{ "sched:sched_stat_runtime", process_sched_runtime_event, },
		{ "sched:sched_wakeup",	      process_sched_wakeup_event, },
		{ "sched:sched_wakeup_new",   process_sched_wakeup_event, },
		{ "sched:sched_process_fork", process_sched_fork_event, },
		{ "sched:sched_process_exit", process_sched_exit_event, },
		{ "sched:sched_migrate_task", process_sched_migrate_task_event, },
	};
	struct perf_session *session;

	session = perf_session__new(sched->input_name, O_RDONLY, 0, false, &sched->tool);
	if (session == NULL) {
		pr_debug("No Memory for session\n");
		return -1;
	}

	if (perf_session__set_tracepoints_handlers(session, handlers))
		goto out_delete;

	if (perf_session__has_traces(session, "record -R")) {
		int err = perf_session__process_events(session, &sched->tool);
		if (err) {
			pr_err("Failed to process events, error %d", err);
			goto out_delete;
		}

		sched->nr_events      = session->hists.stats.nr_events[0];
		sched->nr_lost_events = session->hists.stats.total_lost;
		sched->nr_lost_chunks = session->hists.stats.nr_events[PERF_RECORD_LOST];
	}

	if (destroy)
		perf_session__delete(session);

	if (psession)
		*psession = session;

	return 0;

out_delete:
	perf_session__delete(session);
	return -1;
}

static void print_bad_events(struct perf_sched *sched)
{
	if (sched->nr_unordered_timestamps && sched->nr_timestamps) {
		printf("  INFO: %.3f%% unordered timestamps (%ld out of %ld)\n",
			(double)sched->nr_unordered_timestamps/(double)sched->nr_timestamps*100.0,
			sched->nr_unordered_timestamps, sched->nr_timestamps);
	}
	if (sched->nr_lost_events && sched->nr_events) {
		printf("  INFO: %.3f%% lost events (%ld out of %ld, in %ld chunks)\n",
			(double)sched->nr_lost_events/(double)sched->nr_events * 100.0,
			sched->nr_lost_events, sched->nr_events, sched->nr_lost_chunks);
	}
	if (sched->nr_state_machine_bugs && sched->nr_timestamps) {
		printf("  INFO: %.3f%% state machine bugs (%ld out of %ld)",
			(double)sched->nr_state_machine_bugs/(double)sched->nr_timestamps*100.0,
			sched->nr_state_machine_bugs, sched->nr_timestamps);
		if (sched->nr_lost_events)
			printf(" (due to lost events?)");
		printf("\n");
	}
	if (sched->nr_context_switch_bugs && sched->nr_timestamps) {
		printf("  INFO: %.3f%% context switch bugs (%ld out of %ld)",
			(double)sched->nr_context_switch_bugs/(double)sched->nr_timestamps*100.0,
			sched->nr_context_switch_bugs, sched->nr_timestamps);
		if (sched->nr_lost_events)
			printf(" (due to lost events?)");
		printf("\n");
	}
}

static int perf_sched__analyze(struct perf_sched *sched)
{
	int sz;
	int i;
	u64 dur, start, end;
	char buf[BUFSIZ];

	sched->analyze_maxcpu = sysconf(_SC_NPROCESSORS_CONF);

	sz = sched->analyze_maxcpu * sizeof(*sched->analyze);
	sched->analyze = malloc(sz);
	BUG_ON(sched->analyze == NULL);

	memset(sched->analyze, 0, sz);

	for (i = 0; i < sched->analyze_maxcpu; i++) {
		sched->analyze[i].capture_start = (u64)-1LLU;
		sched->analyze[i].capture_end = (u64)-1LLU;
	}

	setup_pager();
	if (perf_sched__read_events(sched, true, NULL))
		return -1;

	/* find total span */
	start = (u64)-1LLU;
	end = (u64)-1LLU;
	for (i = 0; i < sched->analyze_maxcpu; i++) {
		if (start == (u64)-1LLU || start > sched->analyze[i].capture_start)
			start = sched->analyze[i].capture_start;
		if (end == (u64)-1LLU || end < sched->analyze[i].capture_end)
			end = sched->analyze[i].capture_end;
	}
	dur = end - start;

	printf("CPU utilization chart\n");
	printf("%3s | %14s | %24s |\n",
		"CPU", "Duration", "Busy");
	printf("%3s | %14s | %24s |\n",
		"---", "--------", "----");
	for (i = 0; i < sched->analyze_maxcpu; i++) {
		printf("%3d | ", i);
		snprintf(buf, sizeof(buf) - 1, "%12" PRIu64, dur);
		printf("%14s | ", buf);
		snprintf(buf, sizeof(buf) - 1, "%12" PRIu64 " %%%4.1f" ,
				sched->analyze[i].runtime,
				((double)(sched->analyze[i].runtime * 100.0) / dur));
		printf("%24s |\n", buf);
	}

	free(sched->analyze);
	sched->analyze = NULL;

	return 0;
}

static int perf_sched__lat(struct perf_sched *sched)
{
	struct rb_node *next;
	struct perf_session *session;

	setup_pager();
	if (perf_sched__read_events(sched, false, &session))
		return -1;
	perf_sched__sort_lat(sched);

	printf("\n ---------------------------------------------------------------------------------------------------------------\n");
	printf("  Task                  |   Runtime ms  | Switches | Average delay ms | Maximum delay ms | Maximum delay at     |\n");
	printf(" ---------------------------------------------------------------------------------------------------------------\n");

	next = rb_first(&sched->sorted_atom_root);

	while (next) {
		struct work_atoms *work_list;

		work_list = rb_entry(next, struct work_atoms, node);
		output_lat_thread(sched, work_list);
		next = rb_next(next);
	}

	printf(" -----------------------------------------------------------------------------------------\n");
	printf("  TOTAL:                |%11.3f ms |%9" PRIu64 " |\n",
		(double)sched->all_runtime / 1e6, sched->all_count);

	printf(" ---------------------------------------------------\n");

	print_bad_events(sched);
	printf("\n");

	perf_session__delete(session);
	return 0;
}

static int perf_sched__map(struct perf_sched *sched)
{
	sched->max_cpu = sysconf(_SC_NPROCESSORS_CONF);

	setup_pager();
	if (perf_sched__read_events(sched, true, NULL))
		return -1;
	print_bad_events(sched);
	return 0;
}

static int perf_sched__replay(struct perf_sched *sched)
{
	unsigned long i;

	calibrate_run_measurement_overhead(sched);
	calibrate_sleep_measurement_overhead(sched);

	test_calibrations(sched);

	if (perf_sched__read_events(sched, true, NULL))
		return -1;

	printf("nr_run_events:        %ld\n", sched->nr_run_events);
	printf("nr_sleep_events:      %ld\n", sched->nr_sleep_events);
	printf("nr_wakeup_events:     %ld\n", sched->nr_wakeup_events);

	if (sched->targetless_wakeups)
		printf("target-less wakeups:  %ld\n", sched->targetless_wakeups);
	if (sched->multitarget_wakeups)
		printf("multi-target wakeups: %ld\n", sched->multitarget_wakeups);
	if (sched->nr_run_events_optimized)
		printf("run atoms optimized: %ld\n",
			sched->nr_run_events_optimized);

	print_task_traces(sched);
	add_cross_task_wakeups(sched);

	create_tasks(sched);
	printf("------------------------------------------------------------\n");
	for (i = 0; i < sched->replay_repeat; i++)
		run_one_test(sched);

	return 0;
}

static void setup_sorting(struct perf_sched *sched, const struct option *options,
			  const char * const usage_msg[])
{
	char *tmp, *tok, *str = strdup(sched->sort_order);

	for (tok = strtok_r(str, ", ", &tmp);
			tok; tok = strtok_r(NULL, ", ", &tmp)) {
		if (sort_dimension__add(tok, &sched->sort_list) < 0) {
			error("Unknown --sort key: `%s'", tok);
			usage_with_options(usage_msg, options);
		}
	}

	free(str);

	sort_dimension__add("pid", &sched->cmp_pid);
}

static int __cmd_record(int argc, const char **argv)
{
	unsigned int rec_argc, i, j;
	const char **rec_argv;
	const char * const record_args[] = {
		"record",
		"-a",
		"-R",
		"-f",
		"-m", "1024",
		"-c", "1",
		"-e", "sched:sched_switch",
		"-e", "sched:sched_stat_wait",
		"-e", "sched:sched_stat_sleep",
		"-e", "sched:sched_stat_iowait",
		"-e", "sched:sched_stat_runtime",
		"-e", "sched:sched_process_exit",
		"-e", "sched:sched_process_fork",
		"-e", "sched:sched_wakeup",
		"-e", "sched:sched_migrate_task",
	};

	rec_argc = ARRAY_SIZE(record_args) + argc - 1;
	rec_argv = calloc(rec_argc + 1, sizeof(char *));

	if (rec_argv == NULL)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(record_args); i++)
		rec_argv[i] = strdup(record_args[i]);

	for (j = 1; j < (unsigned int)argc; j++, i++)
		rec_argv[i] = argv[j];

	BUG_ON(i != rec_argc);

	return cmd_record(i, rec_argv, NULL);
}

/**************************************************************************/

enum task_action_type {
	TA_END,
	TA_BURN,
	TA_SLEEP,
	TA_SPAWN,
	TA_EXIT,
	TA_CLONE_PARENT,
	TA_CLONE_CHILD,
	TA_WAIT_ID,
	TA_SIGNAL_ID
};

struct task_action {
	enum task_action_type action;
	union {
		struct { u64 nsecs; } burn;
		struct { u64 nsecs; } sleep;
		struct { u64 nsecs; } spawn;
		struct { int ret; } exit;
		struct { int child_pid;  } clone_parent;
		struct { int parent_pid; } clone_child;
		struct { unsigned long id; } wait_id;
		struct { unsigned long id; } signal_id;
	} u;
};

#define T(x)	((u64)((double)(x) * 1E9))

struct task {
	const char *name;
	int pid;
	const struct task_action *actions;
};

struct task_run {
	struct playback *playback;	/* point back to the playback */
	const struct task *task;	/* task */
	const struct task_action *current_action;
	char name[BUFSIZ];		/* lots of space for a name */
	int id;
	pid_t real_pid;
	pid_t parent_pid;		/* when created by CLONE_PARENT */
	u64 start_time;		/* time when the current task starts */
	u64 local_time;		/* local time (beginning from 0) */
	int children_count;

	int futex_int;
};

struct playback_info {
	int task_cnt;
	int futex_cnt;
	int task_off;
	int futex_off;
	int work_area_size;
};

struct playback {
	struct perf_sched *sched;
	struct playback_info info;

	u64 origin_time;		/* time when the simulation starts */
	int task_count;
	struct task_run *task_runs;
	int futex_count;
	int *futexes;

	unsigned int flags;		/* flags */
#define PF_ABSOLUTE_TIME		1
#define PF_RELATIVE_TIME		2
#define PF_TIME_MASK			3

	int debug_level;

	int spawn_count;		/* left to spawn */
	int exited_count;		/* left to exit */
	int forked_count;		/* initially forked */
};

static inline int playback_absolute_time(const struct playback *p)
{
	return ((p->flags & PF_TIME_MASK) == PF_ABSOLUTE_TIME);
}
static inline int playback_relative_time(const struct playback *p)
{
	return ((p->flags & PF_TIME_MASK) == PF_RELATIVE_TIME);
}
static inline void playback_set_absolute_time(struct playback *p)
{
	p->flags = (p->flags & ~PF_TIME_MASK) | PF_ABSOLUTE_TIME;
}

static inline void playback_set_relative_time(struct playback *p)
{
	p->flags = (p->flags & ~PF_TIME_MASK) | PF_ABSOLUTE_TIME;
}

static inline void playback_set_debug_level(struct playback *p, int debug_level)
{
	p->debug_level = debug_level;
}

static const char *task_action_str(u64 local_ts, const struct task_action *ta);
const struct task_action *task_action_current(struct task_run *tr);
void task_action_advance(struct task_run *tr);

void vtprintf(struct task_run *tr, const char *fmt, va_list ap);
void tprintf(struct task_run *tr, const char *fmt, ...) __attribute__((__format__(__printf__,2,3)));

void vtprintf(struct task_run *tr, const char *fmt, va_list ap)
{
	struct playback *p = tr->playback;
	int n, size;
	char *str = NULL;

	if (p->debug_level <= 0)
		return;

	size = 256;	/* start with 80 chars (40 * 2) */
	do {
		size *= 2;
		str = realloc(str, size);
		BUG_ON(str == NULL);
		/* Try to print in the allocated space. */
		n = vsnprintf(str, size, fmt, ap);
	} while (n <  0 || n >= size);

	printf("#%2d [%16" PRIu64 " %16" PRIu64 "] %s", tr->id,
			tr->local_time,
			get_nsecs() - p->origin_time,
			str);
	free(str);
}

void tprintf(struct task_run *tr, const char *fmt, ...)
{
	struct playback *p;
	va_list ap;

	p = tr->playback;

	if (p->debug_level <= 0)
		return;

	va_start(ap, fmt);
	vtprintf(tr, fmt, ap);
	va_end(ap);
}


const struct task_action *task_action_current(struct task_run *tr)
{
	if (tr->current_action->action == TA_END)
		return NULL;
	return tr->current_action;
}

void task_action_advance(struct task_run *tr)
{
	if (tr->current_action->action != TA_END)
		tr->current_action++;
}

struct task_action_desc {
	unsigned int id;
	const char *name;
	void (*execute)(struct task_run *tr, const struct task_action *ta);
};

static void execute_task(struct task_run *tr) __attribute__((__noreturn__));

/* END is not processed */

static void execute_spawn(struct task_run *tr __maybe_unused,
		const struct task_action *ta __maybe_unused)
{
	/* we do nothing */
}

static void execute_burn(struct task_run *tr, const struct task_action *ta)
{
	struct playback *p = tr->playback;
	struct perf_sched *sched = p->sched;
	u64 t1, dt, target;

	t1 = get_nsecs();
	dt = ta->u.burn.nsecs;

	if (playback_absolute_time(p))
		target = p->origin_time + tr->local_time + dt;
	else
		target = t1 + dt;

	if (target <= t1) {
		tprintf(tr, "%s %" PRIu64 " - SKIPPED; slip of %" PRIu64 "ns\n",
				"BURN", ta->u.burn.nsecs, t1 - target);
		return;
	}

	tprintf(tr, "%s %" PRIu64 ":%" PRIi64 "\n", "BURN",
			ta->u.burn.nsecs, (int64_t)(target - t1));

	if (!sched->bogoburn)
		burn_nsecs(sched, target - t1);
	else
		bogoburn_nsecs(sched, target - t1);

	tr->local_time += dt;
}

static void execute_sleep(struct task_run *tr, const struct task_action *ta)
{
	struct playback *p = tr->playback;
	u64 t1, dt, target;

	t1 = get_nsecs();
	dt = ta->u.sleep.nsecs;

	if (playback_absolute_time(p))
		target = p->origin_time + tr->local_time + dt;
	else
		target = t1 + dt;

	if (target <= t1) {
		tprintf(tr, "%s %" PRIu64 " - SKIPPED; slip of %" PRIu64 "ns\n",
				"SLEEP", ta->u.sleep.nsecs, t1 - target);
		return;
	}

	tprintf(tr, "%s %" PRIu64 ":%" PRIi64 "\n", "SLEEP",
			ta->u.burn.nsecs, (int64_t)(target - t1));

	sleep_nsecs(target - t1);	/* bogomips */

	tr->local_time += dt;
}

static void execute_exit(struct task_run *tr, const struct task_action *ta)
{
	struct playback *p = tr->playback;
	struct task_run *tr1;
	pid_t real_pid;
	int i, status;

	tprintf(tr, "%s\n", "EXIT");

	while (tr->children_count > 0) {
		real_pid = wait(&status);
		if (real_pid < 0) {
			fprintf(stderr, "panto-perf: Wait failed: %s:%d\n", __func__, __LINE__);
			exit(EXIT_FAILURE);
 		}
		if (!WIFEXITED(status))
			continue;

		/* locate child */
		for (i = 0, tr1 = p->task_runs; i < p->task_count; i++, tr1++)
			if (real_pid == tr1->real_pid)
				break;
		assert(i < p->task_count);

		tr->children_count--;
	}
	exit(ta->u.exit.ret);
}

static void execute_clone_parent(struct task_run *tr, const struct task_action *ta)
{
	struct playback *p = tr->playback;
	struct task_run *tr1;
	int i, pid;
	pid_t real_pid;

	pid = ta->u.clone_parent.child_pid;

	tprintf(tr, "%s %d\n", "CLONE_PARENT", ta->u.clone_parent.child_pid);

	/* locate child */
	for (i = 0, tr1 = p->task_runs; i < p->task_count; i++, tr1++)
		if (pid == tr1->task->pid)
			break;
	assert(i < p->task_count);

	tr1->parent_pid = getpid();

	/* all clones are for now forks */
	real_pid = fork();
	assert(real_pid >= 0);

	if (real_pid == 0) {	/* child */
		tr1->real_pid = getpid();
		tr1->start_time = tr->start_time + tr->local_time;
		tr1->local_time = tr->local_time;
		execute_task(tr1);
	}
	tr1->real_pid = real_pid;
	tr->children_count++;
}

static void execute_clone_child(struct task_run *tr, const struct task_action *ta)
{
	struct playback *p = tr->playback;

	(void)p;

	/* nothing */
	tprintf(tr, "%s %d\n", "CLONE_CHILD", ta->u.clone_child.parent_pid);
}

static void execute_wait_id(struct task_run *tr, const struct task_action *ta)
{
	struct playback *p = tr->playback;
	int *futex_ptr;
	u64 t1, dt;
	int ret;

	t1 = get_nsecs();

	tprintf(tr, "%s %lu\n", "WAIT_ID", ta->u.wait_id.id);

	/* wait for someone to wake us up */
	futex_ptr = p->futexes + ta->u.wait_id.id;
	while (!__sync_bool_compare_and_swap(futex_ptr, 1, 0)) {
		do {
			ret = syscall(SYS_futex, futex_ptr, FUTEX_WAIT, 0, NULL, NULL, 0);
		} while (ret == EINTR);
		assert(ret == 0 || ret == EWOULDBLOCK);
	}

	dt = get_nsecs() - t1;

	tr->local_time += dt;
}

static void execute_signal_id(struct task_run *tr, const struct task_action *ta)
{
	struct playback *p = tr->playback;
	int *futex_ptr;
	int ret;

	tprintf(tr, "%s %lu\n", "SIGNAL_ID", ta->u.signal_id.id);

	/* signal wake up for the other thread */
	futex_ptr = p->futexes + ta->u.signal_id.id;
	if (__sync_bool_compare_and_swap(futex_ptr, 0, 1)) {
		ret = syscall(SYS_futex, futex_ptr, FUTEX_WAKE, 0, NULL, NULL, 0);
		assert(ret >= 0);
	}

	/* local time does not advance */
}

static const struct task_action_desc action_table[] = {
	[TA_END] = {
		.id		= TA_END,
		.name		= "END",
	},
	[TA_SPAWN] = {
		.id		= TA_SPAWN,
		.name		= "SPAWN",
		.execute	= execute_spawn,
	},
	[TA_BURN] = {
		.id		= TA_BURN,
		.name		= "BURN",
		.execute	= execute_burn,
	},
	[TA_SLEEP] = {
		.id		= TA_SLEEP,
		.name		= "SLEEP",
		.execute	= execute_sleep,
	},
	[TA_EXIT] = {
		.id		= TA_EXIT,
		.name		= "EXIT",
		.execute	= execute_exit,
	},
	[TA_CLONE_PARENT] = {
		.id		= TA_CLONE_PARENT,
		.name		= "CLONE_PARENT",
		.execute	= execute_clone_parent,
	},
	[TA_CLONE_CHILD] = {
		.id		= TA_CLONE_CHILD,
		.name		= "CLONE_CHILD",
		.execute	= execute_clone_child,
	},
	[TA_WAIT_ID] = {
		.id		= TA_WAIT_ID,
		.name		= "WAIT_ID",
		.execute	= execute_wait_id,
	},
	[TA_SIGNAL_ID] = {
		.id		= TA_SIGNAL_ID,
		.name		= "SIGNAL_ID",
		.execute	= execute_signal_id,
	},
};

static void execute_task(struct task_run *tr)
{
	const struct task *t;
	const struct task_action *ta;
	struct playback *p;

	t = tr->task;
	assert(t != NULL);

	p = tr->playback;
	assert(p != NULL);

	/* copy name from the task and inform */
	snprintf(tr->name, sizeof(tr->name) - 1, ":%s-%d", t->name, t->pid);
	tr->name[sizeof(tr->name) - 1] = '\0';
	prctl(PR_SET_NAME, tr->name);

	/* skip over spawn */
	while ((ta = task_action_current(tr)) != NULL && ta->action == TA_SPAWN) {
		tr->local_time += ta->u.spawn.nsecs;
		task_action_advance(tr);
	}

	tprintf(tr, "start: name %s, pid %d\n", t->name, t->pid);

	while ((ta = task_action_current(tr)) != NULL) {
		/* verify size */
		assert((unsigned int)ta->action < ARRAY_SIZE(action_table));
		(*action_table[ta->action].execute)(tr, ta);

		task_action_advance(tr);
	}

	exit(0);
}

static void dump_task(const struct task *t)
{
	const struct task_action *ta;
	u64 ts;

	printf("TASK: name %s, pid %d\n", t->name, t->pid);

	ts = 0;
	for (ta = t->actions; ; ta++) {

		if (ta->action == TA_SPAWN)
			ts = ta->u.spawn.nsecs;

		printf("%s\n", task_action_str(ts, ta));
		if (ta->action == TA_END)
			break;

		if (ta->action == TA_BURN)
			ts += ta->u.burn.nsecs;
		else if (ta->action == TA_SLEEP)
			ts += ta->u.sleep.nsecs;
	}
}

static void generate_task(const struct task *t)
{
	const struct task_action *ta;

	printf("[%s/%d]\n", t->name, t->pid);

	for (ta = t->actions; ; ta++) {

		switch (ta->action) {
			case TA_BURN:
				printf("\tburn %" PRIu64 "\n", ta->u.burn.nsecs);
				break;
			case TA_SLEEP:
				printf("\tsleep %" PRIu64 "\n", ta->u.sleep.nsecs);
				break;
			case TA_SPAWN:
				printf("\tspawn %" PRIu64 "\n", ta->u.spawn.nsecs);
				break;
			case TA_CLONE_PARENT:
				printf("\tclone-parent %d\n", ta->u.clone_parent.child_pid);
				break;
			case TA_CLONE_CHILD:
				printf("\tclone-child %d\n", ta->u.clone_child.parent_pid);
				break;
			case TA_WAIT_ID:
				printf("\twait-id %lu\n", ta->u.wait_id.id);
				break;
			case TA_SIGNAL_ID:
				printf("\tsignal-id %lu\n", ta->u.signal_id.id);
				break;
			case TA_EXIT:
				printf("\texit %d\n", ta->u.exit.ret);
				break;
			case TA_END:
				printf("\tend\n");
			default:
				break;
		}

		if (ta->action == TA_END)
			break;
	}
}

static void fill_playback_info(struct playback_info *pi, const struct task * const * tasks_array)
{
	const struct task *t;
	const struct task * const *tt;
	const struct task_action *ta;
	unsigned long id, maxid;
	int pagesize;

	/* get page size */
	pagesize = getpagesize();

	/* make sure it's a power of two */
	assert((pagesize & (pagesize - 1)) == 0);

	/* align work area to 16 bytes */
	pi->work_area_size = ALIGN(sizeof(struct playback), 16);
	pi->task_off = pi->work_area_size;

	/* count number of tasks (and find maximum futex id) */
	maxid = -1;
	pi->task_cnt = 0;
	tt = tasks_array;
	while ((t = *tt++) != NULL) {
		pi->task_cnt++;
		for (ta = t->actions; ta != NULL && ta->action != TA_END; ta++) {
			if (ta->action == TA_WAIT_ID)
				id = ta->u.wait_id.id;
			else if (ta->action == TA_SIGNAL_ID)
				id = ta->u.signal_id.id;
			else
				continue;

			if (id > maxid || maxid == (unsigned long)-1)
				maxid = id;
		}
	}
	pi->futex_cnt = maxid + 1;

	/* add the size of the task structs */
	pi->work_area_size += ALIGN(sizeof(struct task_run) * pi->task_cnt, 16);
	pi->futex_off = pi->work_area_size;

	/* add the size of the futexes */
	pi->work_area_size += ALIGN(sizeof(int) * pi->futex_cnt, 16);

	/* now align to the pagesize (we have verified that pagesize is a power of two) */
	pi->work_area_size = ALIGN(pi->work_area_size, pagesize);

	printf("#%d tasks, #%d futexes, total work area size %d\n",
			pi->task_cnt, pi->futex_cnt, pi->work_area_size);

}

static struct playback *playback_create(struct perf_sched *sched,
		const struct task * const *tasks_array)
{
	struct playback_info pi;
	const struct task * const *tt;
	struct task_run *tr;
	int i;
	void *work_area;
	struct playback *p;

	assert(tasks_array != NULL);

	/* layout playback structure according to inputs */
	fill_playback_info(&pi, tasks_array);

	/* map the shared memory across all processes */
	work_area = mmap(NULL, pi.work_area_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	assert(work_area != MAP_FAILED);

	memset(work_area, 0, pi.work_area_size);

	sched->playback = work_area;

	p = sched->playback;
	p->sched = sched;

	memcpy(&p->info, &pi, sizeof(pi));

	p->origin_time = 0;
	p->task_count = pi.task_cnt;
	p->task_runs = work_area + pi.task_off;
	p->futex_count = pi.futex_cnt;
	p->futexes = work_area + pi.futex_off;

	p->spawn_count = 0;
	p->exited_count = 0;
	p->forked_count = 0;

	for (i = 0, tr = p->task_runs, tt = tasks_array; i < p->task_count;
			i++, tr++, tt++) {

		tr->playback = p;
		tr->task = *tt;
		tr->current_action = tr->task->actions;
		tr->id = i;
		tr->real_pid = -1;
		tr->start_time = 0;
		tr->local_time = 0;
		tr->futex_int = 0;
	}

	return p;
}

static void playback_destroy(struct playback *p)
{
	assert(p != NULL);

	munmap(p, p->info.work_area_size);
}

static void playback_run(struct playback *p)
{
	struct task_run *tr, *tr1;
	const struct task *t;
	const struct task_action *ta;
	int i, status;
	pid_t real_pid;
	uint64_t curr_nsecs;

	p->origin_time = get_nsecs();

	p->spawn_count = 0;
	for (i = 0; i < p->task_count; i++) {
		tr = &p->task_runs[i];
		t = tr->task;
		if (t->actions->action == TA_SPAWN) {
			p->spawn_count++;
			continue;
		}

		/* don't bother with children */
		if (t->actions->action == TA_CLONE_CHILD)
			continue;

		real_pid = fork();
		assert(real_pid >= 0);

		if (real_pid == 0) {
			/* fill up for the child */
			tr->start_time = get_nsecs();
			tr->real_pid = getpid();
			execute_task(tr);
		}
		tr->real_pid = real_pid;

		p->forked_count++;
	}

	curr_nsecs = 0;
	while (p->spawn_count > 0) {
		tr1 = NULL;
		for (i = 0; i < p->task_count; i++) {
			tr = &p->task_runs[i];
			t = tr->task;
			ta = t->actions;

			if (tr->real_pid >= 0 || ta->action != TA_SPAWN)
				continue;

			if (tr1 == NULL || tr1->task->actions->u.spawn.nsecs > ta->u.spawn.nsecs)
				tr1 = tr;
		}
		assert(tr1 != NULL);

		tr = tr1;
		ta = t->actions;
		sleep_nsecs(ta->u.spawn.nsecs - curr_nsecs);

		real_pid = fork();
		assert(real_pid >= 0);

		if (real_pid == 0) {
			/* fill up for the child */
			tr->start_time = get_nsecs();
			tr->real_pid = getpid();
			execute_task(tr);
		}
		tr->real_pid = real_pid;

		curr_nsecs += (ta->u.spawn.nsecs - curr_nsecs);
		p->spawn_count--;
		p->forked_count++;
	}

	while (p->forked_count > 0) {
		real_pid = wait(&status);
		if (real_pid < 0) {
			fprintf(stderr, "panto-perf: Wait failed: %s:%d\n", __func__, __LINE__);
			exit(EXIT_FAILURE);
		}
		if (!WIFEXITED(status))
			continue;

		for (i = 0; i < p->task_count; i++) {
			tr = &p->task_runs[i];
			t = tr->task;
			if (tr->real_pid == real_pid)
				break;
		}

		assert(i < p->task_count);
		tr->real_pid = -1;
		p->forked_count--;
	}
}

static int parse_select_option(const struct option *opt, const char *str,
			int unset __maybe_unused)
{
	struct list_head *lh = (struct list_head *)opt->value;
	struct select_list_entry *sle;

	sle = zalloc(sizeof(*sle));
	BUG_ON(sle == NULL);

	INIT_LIST_HEAD(&sle->node);
	if (isdigit(*str)) {
		sle->pid = atoi(str);
	} else {
		sle->pid = -1;
		sle->name = strdup(str);
		BUG_ON(sle->name == NULL);
	}

	list_add_tail(&sle->node, lh);

	return 0;
}

static const char *task_state_str(unsigned int task_state)
{
	static const char * const task_state_array[] = {
		"R (running)",		/*   0 */
		"S (sleeping)",		/*   1 */
		"D (disk sleep)",	/*   2 */
		"T (stopped)",		/*   4 */
		"t (tracing stop)",	/*   8 */
		"Z (zombie)",		/*  16 */
		"X (dead)",		/*  32 */
		"x (dead)",		/*  64 */
		"K (wakekill)",		/* 128 */
		"W (waking)",		/* 256 */
	};
	const char * const *p = &task_state_array[0];
	unsigned int state = task_state & 511;

	while (state) {
		p++;
		state >>= 1;
	}
	return *p;
}

static void calculate_replay_start_time(struct perf_sched *sched)
{
	struct sched_atom *atom;
	struct task_desc *task;
	unsigned long i;

	sched->replay_start_time = (u64)-1;	/* maximum possible */
	for (i = 0; i < sched->nr_tasks; i++) {
		task = sched->tasks[i];

		if (task->nr_events == 0)
			continue;

		atom = task->atoms[0];

		if (atom->timestamp < sched->replay_start_time)
			sched->replay_start_time = atom->timestamp;

	}
	if (sched->replay_start_time == (u64)-1)
		sched->replay_start_time = 0;
}

static void calculate_replay_end_time(struct perf_sched *sched)
{
	struct sched_atom *atom;
	struct task_desc *task;
	unsigned long i;
	u64 ts_end;

	sched->replay_end_time = 0;	/* minimum */
	for (i = 0; i < sched->nr_tasks; i++) {
		task = sched->tasks[i];

		if (task->nr_events == 0)
			continue;

		atom = task->atoms[task->nr_events - 1];

		ts_end = atom->timestamp;
		if (atom->type == SCHED_EVENT_RUN)
			ts_end += atom->duration;

		if (ts_end > sched->replay_end_time)
			sched->replay_end_time = ts_end;
	}
}

static const char *sched_atom_str(struct perf_sched *sched,
		const struct sched_atom *atom)
{
	static char buf[BUFSIZ];
	char *s, *e;
	unsigned int i;

	if (sched->replay_start_time == 0)
		calculate_replay_start_time(sched);

	if (sched->replay_end_time == 0)
		calculate_replay_end_time(sched);

	s = buf;
	e = &buf[ARRAY_SIZE(buf)];

	snprintf(s, e - s, "\t%014" PRIu64 " ",
			atom->timestamp - sched->replay_start_time);
	e[-1] = '\0';
	s += strlen(s);

	switch (atom->type) {
		case SCHED_EVENT_RUN:
			snprintf(s, e - s, "%-10s%014" PRIu64, "RUN",
				atom->duration);
			e[-1] = '\0';
			s += strlen(s);
			break;
		case SCHED_EVENT_SLEEP:
			snprintf(s, e - s, "%-10s %s %d", "SLEEP",
					task_state_str(atom->task_state),
					atom->waker_count);
			e[-1] = '\0';
			s += strlen(s);
			for (i = 0; i < atom->waker_count; i++) {
				snprintf(s, e - s, " [%ld@%014" PRIu64 "]",
					atom->wakers[i]->pid,
					atom->waker_events[i]->timestamp -
						sched->replay_start_time);
				e[-1] = '\0';
				s += strlen(s);
			}
			break;
		case SCHED_EVENT_WAKEUP:
			snprintf(s, e - s, "%-10s", "WAKEUP");
			e[-1] = '\0';
			s += strlen(s);
			if (atom->wakee != NULL && atom->wakee_event != NULL) {
				snprintf(s, e - s, " [%ld@%014" PRIu64 "]",
					atom->wakee->pid,
					atom->wakee_event->timestamp -
						sched->replay_start_time);
				e[-1] = '\0';
				s += strlen(s);
			}
			break;
		case SCHED_EVENT_MIGRATION:
			snprintf(s, e - s, "%-10s", "MIGRATION");
			e[-1] = '\0';
			s += strlen(s);
			break;
		case SCHED_EVENT_EXIT:
			snprintf(s, e - s, "%-10s", "EXIT");
			e[-1] = '\0';
			s += strlen(s);
			break;
		case SCHED_EVENT_FORK_PARENT:
			snprintf(s, e - s, "%-10s %d", "FORK_PARENT",
					atom->pid);
			e[-1] = '\0';
			s += strlen(s);
			break;
		case SCHED_EVENT_FORK_CHILD:
			snprintf(s, e - s, "%-10s %d", "FORK_CHILD",
					atom->pid);
			e[-1] = '\0';
			s += strlen(s);
			break;
		default:
			/* GCC whines about missing default case without this */
			break;
	}

	if (sched->debug > 2 && atom->msg) {
		snprintf(s, e - s, " | %s", atom->msg);
		e[-1] = '\0';
		s += strlen(s);
	}

	return buf;
}

static void dump_sched_atom_task(struct perf_sched *sched,
		struct task_desc *task)
{
	struct sched_atom *atom;
	unsigned long j;
	unsigned int exited;

	exited = 0;
	for (j = 0; j < task->nr_events && !exited; j++) {

		atom = task->atoms[j];

		printf("%s\n", sched_atom_str(sched, atom));

		/* exited = atom->type == SCHED_EVENT_EXIT; */
	}
}

static const char *task_action_str(u64 local_ts, const struct task_action *ta)
{
	static char buf[BUFSIZ];
	char *s, *e;

	s = buf;
	e = &buf[ARRAY_SIZE(buf)];

	snprintf(s, e - s, "[%014" PRIu64 "] %-12s",
			local_ts, action_table[ta->action].name);
	e[-1] = '\0';
	s += strlen(s);

	switch (ta->action) {
		case TA_BURN:
			snprintf(s, e - s, "%014" PRIu64 "ns", ta->u.burn.nsecs);
			break;
		case TA_SLEEP:
			snprintf(s, e - s, "%014" PRIu64 "ns", ta->u.sleep.nsecs);
			break;
		case TA_SPAWN:
			snprintf(s, e - s, "%014" PRIu64 "ns", ta->u.spawn.nsecs);
			break;
		case TA_CLONE_PARENT:
			snprintf(s, e - s, "%d", ta->u.clone_parent.child_pid);
			break;
		case TA_CLONE_CHILD:
			snprintf(s, e - s, "%d", ta->u.clone_child.parent_pid);
			break;
		case TA_WAIT_ID:
			snprintf(s, e - s, "%lu", ta->u.wait_id.id);
			break;
		case TA_SIGNAL_ID:
			snprintf(s, e - s, "%lu", ta->u.signal_id.id);
			break;
		case TA_EXIT:
		case TA_END:
			*s = '\0';
			break;
		default:
			/* GCC is whining about missing default case */
			break;
	}
	e[-1] = '\0';
	s += strlen(s);

	return buf;
}

static struct task *generate_spr_program(struct perf_sched *sched,
		struct task_desc *task,
		unsigned long *map_id_fwd, unsigned long *next_opt_id)
{
	struct sched_atom *atom, *atom_last;
	unsigned long eventnr;
	unsigned int exited;
	unsigned int blocked;
	unsigned int last_blocked;
	unsigned int last_was_runnable;
	unsigned int selected_wakers;
	unsigned int exited_wakers;
	struct task *t;
	struct task_action *ta_alloc;
	int ta_count, ta_max;
	int task_state;
	u64 replay_ts, replay_ts_new;
	u64 local_ts;
	u64 delta_ts;
	u64 start_run_ts;
	int pending_count;
	struct task_action ta_work;
	unsigned int i;
	u64 burn_run_accum;

	BUG_ON(task == NULL);

	BUG_ON(task->nr_events == 0);
#if 0
	/* make sure there are events there */
	if (task->nr_events == 0) {
		return NULL;
	}
#endif

	if (sched->replay_start_time == 0)
		calculate_replay_start_time(sched);

	if (sched->replay_end_time == 0)
		calculate_replay_end_time(sched);

	t = zalloc(sizeof(*t));
	BUG_ON(t == NULL);
	t->pid = task->pid;
	t->name = strdup(task->comm);
	BUG_ON(t->name == NULL);

	ta_count = 0;
	ta_max = 256;	/* starting point */
	ta_alloc = zalloc(sizeof(*ta_alloc) * ta_max);
	BUG_ON(ta_alloc == NULL);
	t->actions = ta_alloc;

#undef APPEND_TA_WORK
#define APPEND_TA_WORK() \
	do { \
		if (ta_count >= ta_max) { \
			ta_alloc = realloc(ta_alloc, ta_max * 2 * (sizeof(*t->actions))); \
			BUG_ON(ta_alloc == NULL); \
			ta_max *= 2; \
			t->actions = ta_alloc; \
		} \
		ta_alloc[ta_count++] = ta_work; \
		if (sched->debug > 2) \
			printf("\t\t%4d: GEN: %4d: [%012" PRIu64 "] %s\n", __LINE__, \
				pending_count, start_run_ts, \
					task_action_str(start_run_ts, &ta_work)); \
	} while (0)

#undef GET_OPTIMIZED_ID
#define GET_OPTIMIZED_ID(x) \
	({ \
		unsigned long _x = (x); \
		BUG_ON(_x >= (sched->next_wake_id + 1)); \
		if (map_id_fwd[_x] == 0) { \
			map_id_fwd[_x] = ++(*next_opt_id); \
			BUG_ON(*next_opt_id == 0); \
		} \
		map_id_fwd[_x]; \
	})

	exited = 0;
	replay_ts = 0;
	local_ts = 0;
	task_state = -1;
	atom  = NULL;
	start_run_ts = 0;
	pending_count = 0;
	last_was_runnable = 0;
	last_blocked = 0;
	burn_run_accum = 0;

	memset(&ta_work, 0, sizeof(ta_work));
	ta_work.action = TA_END;

	for (eventnr = 0; eventnr < task->nr_events && !exited; eventnr++) {

		atom_last = atom;

		atom = task->atoms[eventnr];

		exited = atom->type == SCHED_EVENT_EXIT;

		blocked = 0;
		selected_wakers = 0;
		exited_wakers = 0;

		if (atom->type == SCHED_EVENT_SLEEP) {

			/* check for exited wakers */
			selected_wakers = 0;
			exited_wakers = 0;
			for (i = 0; i < atom->waker_count; i++) {
				if (atom->wakers[i]->selected) {
					selected_wakers++;
					if (atom->waker_events[i]->exited)
						exited_wakers++;
				}
			}

			if (!sched->preserve_time) {
				blocked = (atom->task_state & 511) != 0 &&
					selected_wakers > 0 && selected_wakers > exited_wakers;
			} else
				blocked = 1;
		}

		replay_ts_new = atom->timestamp - sched->replay_start_time;

		/* first one */
		if (eventnr == 0)
			replay_ts = replay_ts_new;

		if (last_was_runnable && !sched->preserve_time)	/* we don't count the time we were runnable */
			delta_ts = 0;
		else
			delta_ts = replay_ts_new - replay_ts;
		last_was_runnable = 0;
		replay_ts = replay_ts_new;

		if (sched->debug > 2)
			printf("[%012" PRIu64 " %012" PRIu64 "] %s\n",
				replay_ts, delta_ts, sched_atom_str(sched, atom));

		/* first one is special (for non-fork children assume we run until the point of start)  */
		if (eventnr == 0 && atom->type != SCHED_EVENT_FORK_CHILD) {
			ta_work.action = TA_BURN;
			ta_work.u.burn.nsecs = replay_ts;
			start_run_ts = 0;
			pending_count = 1;
			burn_run_accum = 0;
		}

		if (eventnr > 0 && pending_count > 0 && blocked != last_blocked) {

			BUG_ON(ta_work.action != TA_BURN && ta_work.action != TA_SLEEP);

			if (ta_work.action == TA_BURN) {
				ta_work.u.burn.nsecs += burn_run_accum + delta_ts;
				if (ta_work.u.burn.nsecs > 0)
					APPEND_TA_WORK();
			} else if (ta_work.action == TA_SLEEP) {
				ta_work.u.sleep.nsecs += delta_ts;
				if (ta_work.u.sleep.nsecs > 0)
					APPEND_TA_WORK();
			}
			start_run_ts = local_ts;
			pending_count = 0;
		}

		switch (atom->type) {
			case SCHED_EVENT_RUN:
				task_state = 0;
				if (pending_count == 0) {
					ta_work.action = TA_BURN;
					if (atom->duration < delta_ts)
						start_run_ts = local_ts - atom->duration;
					else
						start_run_ts = local_ts - delta_ts;
				} else {
					BUG_ON(ta_work.action != TA_BURN);
				}
				ta_work.u.burn.nsecs = 0;	/* always reset */
				burn_run_accum += atom->duration;
				pending_count++;
				break;

			case SCHED_EVENT_SLEEP:
				task_state = atom->task_state & 511;

				/* set when we were running, and switched out */
				last_was_runnable = task_state == 0;

				if (pending_count > 0) {
					BUG_ON(ta_work.action != TA_BURN);
					ta_work.u.burn.nsecs += delta_ts;
					if (blocked) {
						ta_work.u.burn.nsecs += burn_run_accum;
						if (ta_work.u.burn.nsecs > 0)
							APPEND_TA_WORK();
						pending_count = 0;
						burn_run_accum = 0;
					}
				}

				/* if we're not blocked, we skip */
				if (!blocked)
					break;

				if (selected_wakers > 0 && selected_wakers > exited_wakers) {
					ta_work.action = TA_WAIT_ID;
					ta_work.u.wait_id.id = GET_OPTIMIZED_ID(atom->wake_id);
					start_run_ts = local_ts;
					APPEND_TA_WORK();
					pending_count = 0;
				} else {
					ta_work.action = TA_SLEEP;
					ta_work.u.sleep.nsecs = 0;
					start_run_ts = local_ts;
					pending_count = 1;
				}

				break;

			case SCHED_EVENT_WAKEUP:
				/* we were blocked? */
				if (pending_count > 0 && last_blocked) {
					BUG_ON(ta_work.action != TA_SLEEP);
					ta_work.u.sleep.nsecs += delta_ts;
					if (ta_work.u.sleep.nsecs > 0)
						APPEND_TA_WORK();
					start_run_ts = local_ts;
					pending_count = 0;
				}

				/* no target; ignore */
				if (atom->wakee == NULL || atom->wakee_event == NULL ||
						!atom->wakee->selected) {
					if (pending_count > 0) {
						BUG_ON(ta_work.action != TA_BURN);
						ta_work.u.burn.nsecs += delta_ts;
					} else {
						ta_work.action = TA_BURN;
						ta_work.u.burn.nsecs = 0;
						start_run_ts = local_ts;
						burn_run_accum = 0;
					}
					pending_count++;
					break;
				}

				/* target; need to finish the run */
				if (pending_count > 0) {
					BUG_ON(ta_work.action != TA_BURN);
					ta_work.u.burn.nsecs += burn_run_accum + delta_ts;
					if (ta_work.u.burn.nsecs > 0)
						APPEND_TA_WORK();
					pending_count = 0;
				}

				ta_work.action = TA_SIGNAL_ID;
				ta_work.u.signal_id.id = GET_OPTIMIZED_ID(atom->wakee_event->wake_id);
				start_run_ts = local_ts;
				APPEND_TA_WORK();

				/* and we're running */
				ta_work.action = TA_BURN;
				ta_work.u.burn.nsecs = 0;
				start_run_ts = local_ts;
				pending_count = 1;
				burn_run_accum = 0;

				break;

			case SCHED_EVENT_MIGRATION:
				break;
			case SCHED_EVENT_EXIT:
				if (pending_count > 0) {
					BUG_ON(ta_work.action != TA_BURN);
					ta_work.u.burn.nsecs += burn_run_accum + delta_ts;
					if (ta_work.u.burn.nsecs > 0)
						APPEND_TA_WORK();
					pending_count = 0;
				}

				ta_work.action = TA_EXIT;
				ta_work.u.exit.ret = 0;
				start_run_ts = local_ts;
				APPEND_TA_WORK();
				break;
			case SCHED_EVENT_FORK_PARENT:
				BUG_ON(atom->child == NULL);

				if (pending_count > 0) {
					BUG_ON(ta_work.action != TA_BURN);
					ta_work.u.burn.nsecs += delta_ts;

					if (atom->child->selected) {
						ta_work.u.burn.nsecs += burn_run_accum;
						if (ta_work.u.burn.nsecs > 0)
							APPEND_TA_WORK();
						pending_count = 0;
					} else
						pending_count++;
				}

				if (!atom->child->selected) {
					if (verbose)
						printf("Forking parent (%s/%ld) but child (%s/%ld) not selected; ignoring\n",
							task->comm, task->pid, atom->child->comm, atom->child->pid);
					break;
				}

				ta_work.action = TA_CLONE_PARENT;
				ta_work.u.clone_parent.child_pid = atom->pid;
				start_run_ts = local_ts;
				APPEND_TA_WORK();

				/* and we're running */
				ta_work.action = TA_BURN;
				ta_work.u.burn.nsecs = 0;
				start_run_ts = local_ts;
				pending_count = 1;
				burn_run_accum = 0;

				task_state = 0;	/* running */

				break;
			case SCHED_EVENT_FORK_CHILD:
				BUG_ON(eventnr != 0);	/* this _must_ be the first one */
				BUG_ON(atom->parent == NULL);

				if (!atom->parent->selected) {
					if (verbose)
						printf("Forking child (%s/%ld) but parent (%s/%ld) not selected; converting to run\n",
							task->comm, task->pid, atom->parent->comm, atom->parent->pid);

					task_state = 0;
					ta_work.action = TA_BURN;
					ta_work.u.burn.nsecs = 0;
					start_run_ts = local_ts;
					pending_count = 1;
					burn_run_accum = 0;
					break;
				}

				ta_work.action = TA_CLONE_CHILD;
				ta_work.u.clone_child.parent_pid = atom->pid;
				start_run_ts = local_ts;
				APPEND_TA_WORK();

				/* and we're running */
				ta_work.action = TA_BURN;
				ta_work.u.burn.nsecs = 0;
				start_run_ts = local_ts;
				pending_count = 1;
				burn_run_accum = 0;

				task_state = 0;	/* running */

				break;
			default:
				break;
		}

		if (sched->preserve_time || !last_was_runnable)
			local_ts += delta_ts;

		last_blocked = blocked;
	}

	/* stop any runs */
	if (pending_count > 0) {

		BUG_ON(ta_work.action != TA_BURN && ta_work.action != TA_SLEEP);

		/* if the process was running extend till end */
		delta_ts = !exited ?
			(sched->replay_end_time -
			 	(replay_ts + sched->replay_start_time)) :
			0;

		if (ta_work.action == TA_BURN) {
			ta_work.u.burn.nsecs += burn_run_accum + delta_ts;
			if (ta_work.u.burn.nsecs > 0)
				APPEND_TA_WORK();
		} else if (ta_work.action == TA_SLEEP) {
			ta_work.u.sleep.nsecs += delta_ts;
			if (ta_work.u.sleep.nsecs > 0)
				APPEND_TA_WORK();
		}
		pending_count = 0;
	}

	ta_work.action = TA_END;
	ta_work.u.exit.ret = 0;
	start_run_ts = local_ts;
	APPEND_TA_WORK();

	return t;
}

static int read_spr_program(struct perf_sched *sched __maybe_unused,
		const char *file, struct task ***ttt)
{
	FILE *fp;
	char buf[BUFSIZ];
	char orig_buf[BUFSIZ];
	char *name;
	struct task *t, **tt;
	struct task_action ta_work, *ta_alloc;
	int task_count, task_max;
	int ta_count, ta_max;
	char *s, *e, *start, *end;
	int line, pid;

#undef APPEND_TASK
#define APPEND_TASK() \
	do { \
		if (task_count >= task_max) { \
			tt = realloc(tt, (task_max + 32) * (sizeof(*tt))); \
			BUG_ON(tt == NULL); \
			task_max += 32; \
		} \
		tt[task_count++] = t; \
	} while (0)

#undef APPEND_TA_WORK
#define APPEND_TA_WORK() \
	do { \
		if (ta_count >= ta_max) { \
			ta_alloc = realloc(ta_alloc, (ta_max + 4096) * (sizeof(*ta_alloc))); \
			BUG_ON(ta_alloc == NULL); \
			ta_max += 4096; \
		} \
		ta_alloc[ta_count++] = ta_work; \
	} while (0)


	fp = fopen(file, "ra");
	if (fp == NULL) {
		fprintf(stderr, "Could not open file '%s'\n", file);
		return -1;
	}

	task_count = 0;
	task_max = 0;
	tt = NULL;
	ta_count = 0;
	ta_max = 0;
	ta_alloc = NULL;
	pid = -1;
	name = NULL;

	t = NULL;
	line = 0;
	while (fgets(buf, sizeof(buf) - 1, fp) != NULL) {
		line++;

		buf[sizeof(buf) - 1] = '\0';

		/* remove trailing newline */
		s = strrchr(buf, '\n');
		if (s != NULL)
			*s = '\0';

		strcpy(orig_buf, buf);

		/* remove comments */
		s = strchr(buf, '#');
		if (s != NULL)
			*s = '\0';

		/* remove trailing spaces */
		s = buf + strlen(buf) - 1;
		while (s > buf && isspace(*s))
			*s-- = '\0';

		/* skip over spaces in the front */
		s = buf;
		while (isspace(*s))
			s++;
		start = s;
		end = s + strlen(s);

		/* empty line */
		if (start >= end - 1)
			continue;

		/* waiting for task */
		if (t == NULL) {
			if (*start != '[' || end[-1] != ']')
				goto syntax_error;
			s = start + 1;
			e = strrchr(s, '/');
			if (e == NULL)
				goto syntax_error;
			if (e - s < 1)
				goto syntax_error;

			name = malloc(e - s + 1);
			BUG_ON(name == NULL);

			memcpy(name, s, e - s);
			name[e - s] = '\0';

			pid = atoi(e + 1);
			if (pid < 0)
				goto syntax_error;

			ta_count = 0;
			ta_max = 0;
			ta_alloc = NULL;

			/* allocate but don't do anything with it */
			t = malloc(sizeof(*t));
			BUG_ON(t == NULL);

		} else {
			s = start;
			e = start;
			while (!isspace(*e))
				e++;
			*e++ = '\0';
			if (strcmp(s, "burn") == 0) {
				ta_work.action = TA_BURN;
				ta_work.u.burn.nsecs = strtoull(e, NULL, 10);
			} else if (strcmp(s, "sleep") == 0) {
				ta_work.action = TA_SLEEP;
				ta_work.u.sleep.nsecs = strtoull(e, NULL, 10);
			} else if (strcmp(s, "spawn") == 0) {
				ta_work.action = TA_SPAWN;
				ta_work.u.spawn.nsecs = strtoull(e, NULL, 10);
			} else if (strcmp(s, "clone-parent") == 0) {
				ta_work.action = TA_CLONE_PARENT;
				ta_work.u.clone_parent.child_pid = (int)strtoul(e, NULL, 10);
			} else if (strcmp(s, "clone-child") == 0) {
				ta_work.action = TA_CLONE_CHILD;
				ta_work.u.clone_child.parent_pid = (int)strtoul(e, NULL, 10);
			} else if (strcmp(s, "wait-id") == 0) {
				ta_work.action = TA_WAIT_ID;
				ta_work.u.wait_id.id = strtoul(e, NULL, 10);
			} else if (strcmp(s, "signal-id") == 0) {
				ta_work.action = TA_SIGNAL_ID;
				ta_work.u.signal_id.id = strtoul(e, NULL, 10);
			} else if (strcmp(s, "exit") == 0) {
				ta_work.action = TA_EXIT;
				ta_work.u.exit.ret = (int)strtoul(e, NULL, 10);
			} else if (strcmp(s, "end") == 0) {
				ta_work.action = TA_END;
			} else
				goto syntax_error;

			APPEND_TA_WORK();

			if (ta_work.action == TA_END) {
				BUG_ON(t == NULL);
				BUG_ON(name == NULL);
				BUG_ON(pid < 0);

				if (ta_count == 0)
					goto syntax_error;

				t->name = name;
				t->pid = pid;
				t->actions = ta_alloc;

				APPEND_TASK();
				t = NULL;
			}
		}
	}
	t = NULL;
	APPEND_TASK();

	fclose(fp);

	/* no program */
	if (tt == NULL)
		return -1;

	*ttt = tt;
	return 0;

syntax_error:
	fprintf(stderr, "syntax error at line %d: %s\n", line, orig_buf);
	*ttt = NULL;
	fclose(fp);
	return -1;
}

static int perf_sched__spr_replay(struct perf_sched *sched)
{
	struct task_desc *task;
	struct task **tt;
	const struct task * const *task_array;
	struct select_list_entry *sle;
	unsigned long i, j;
	int selected_task_count;
	struct playback *p;
	unsigned long *map_id_fwd;
	unsigned long next_opt_id;
	struct sched_atom *atom;
	u64 run_nsecs;
	int ret;

	/* mark that we're not the standard replay */
	sched->spr_replay = true;

	if (!sched->dry_run && !sched->spr_list) {
		calibrate_run_measurement_overhead(sched);
		calibrate_sleep_measurement_overhead(sched);

		test_calibrations(sched);
	}

	if (sched->spr_filename == NULL) {

		if (perf_sched__read_events(sched, true, NULL))
			return -1;

		if (sched->debug > 0) {
			printf("nr_run_events:        %ld\n",
					sched->nr_run_events);
			printf("nr_sleep_events:      %ld\n",
					sched->nr_sleep_events);
			printf("nr_wakeup_events:     %ld\n",
					sched->nr_wakeup_events);

			if (sched->targetless_wakeups)
				printf("target-less wakeups:  %ld\n",
						sched->targetless_wakeups);
			if (sched->multitarget_wakeups)
				printf("multi-target wakeups: %ld\n",
						sched->multitarget_wakeups);
			if (sched->nr_run_events_optimized)
				printf("run atoms optimized: %ld\n",
					sched->nr_run_events_optimized);
		}

		calculate_replay_start_time(sched);
		calculate_replay_end_time(sched);

		selected_task_count = 0;
		for (i = 0; i < sched->nr_tasks; i++) {
			task = sched->tasks[i];

			/* if no entries, then everything is selected */
			if (!list_empty(&sched->select_list)) {
				list_for_each_entry(sle, &sched->select_list, node) {
					task->selected = sle->pid == -1 ?
							strcmp(sle->name, task->comm) == 0 :
							sle->pid == (int)task->pid;
					if (task->selected)
						break;
				}
			} else
				task->selected = 1;
			selected_task_count += task->selected;
		}

		tt = zalloc((selected_task_count + 1) * sizeof(*tt));
		BUG_ON(tt == NULL);

		if (sched->spr_list) {
			for (j = 0; j < sched->nr_tasks; j++) {
				task = sched->tasks[j];

				/* task with no events, doesn't show up */
				if (task->nr_events == 0)
					continue;

				run_nsecs = 0;
				for (i = 0; i < task->nr_events; i++) {
					atom = task->atoms[i];
					if (atom->type == SCHED_EVENT_EXIT)
						break;
					if (atom->type == SCHED_EVENT_RUN)
						run_nsecs += atom->duration;
				}

				printf("[%s/%ld] R:%" PRIu64 "\n",
					task->comm, task->pid, run_nsecs);
			}
		}

		if (sched->debug > 1) {
			printf("Dump of scheduling atoms\n");
			for (i = 0; i < sched->nr_tasks; i++) {
				task = sched->tasks[i];

				if (task->nr_events == 0 || !task->selected)
					continue;

				printf("task %6ld (%20s:%10ld), nr_events: %ld\n",
					task->nr, task->comm, task->pid, task->nr_events);

				dump_sched_atom_task(sched, task);
				printf("\n");
			}
			printf("\n");
		}

		/* map of a wake id to an optimized wake id */
		map_id_fwd = zalloc((sched->next_wake_id + 1) * sizeof(*map_id_fwd));
		BUG_ON(map_id_fwd == NULL);

		next_opt_id = 0;

		if (verbose)
			printf("Generating replay program\n");

		for (i = 0, j = 0; i < sched->nr_tasks; i++) {
			task = sched->tasks[i];

			if (task->nr_events == 0 || !task->selected)
				continue;

			if (verbose)
				printf("task %6ld (%20s:%10ld), nr_events: %ld\n",
					task->nr, task->comm, task->pid, task->nr_events);

			tt[j] = generate_spr_program(sched, task, map_id_fwd, &next_opt_id);
			BUG_ON(tt[j] == NULL);

			if (sched->debug > 1) {
				dump_task(tt[j]);
				printf("\n");
			}

			j++;
		}

		if (sched->generate) {
			for (i = 0; tt[i] != NULL; i++)
				generate_task(tt[i]);
		}

		free(map_id_fwd);

	} else {
		ret = read_spr_program(sched, sched->spr_filename, &tt);
		BUG_ON(ret != 0);

		if (sched->generate) {
			for (i = 0; tt[i] != NULL; i++)
				generate_task(tt[i]);
		}

	}

	if (!sched->dry_run) {

		if (sched->bogoburn) {

			if (sched->bogoloops == 0)
				calculate_bogoloops_value(sched);

			if (sched->debug > 0)
				printf("bogoloops at %" PRIu64 "\n",
						sched->bogoloops);
		}

		task_array = (void *)tt;

		p = playback_create(sched, task_array);
		BUG_ON(p == NULL);

		playback_set_debug_level(p, sched->debug);

		if (verbose)
			printf("Running...\n");
		playback_run(p);

		if (verbose)
			printf("Done...\n");

		playback_destroy(p);
	}

	/* free */
	for (i = 0; tt[i] != NULL; i++) {
		free((void *)tt[i]->actions);
		free((void *)tt[i]->name);
		free(tt[i]);
	}
	free(tt);

	return 0;
}

int cmd_sched(int argc, const char **argv, const char *prefix __maybe_unused)
{
	const char default_sort_order[] = "avg, max, switch, runtime";
	struct perf_sched sched = {
		.tool = {
			.sample		 = perf_sched__process_tracepoint_sample,
			.comm		 = perf_event__process_comm,
			.lost		 = perf_event__process_lost,
			.fork		 = perf_event__process_task,
			.exit		 = perf_event__process_task,
			.ordered_samples = true,
		},
		.cmp_pid	      = LIST_HEAD_INIT(sched.cmp_pid),
		.sort_list	      = LIST_HEAD_INIT(sched.sort_list),
		.start_work_mutex     = PTHREAD_MUTEX_INITIALIZER,
		.work_done_wait_mutex = PTHREAD_MUTEX_INITIALIZER,
		.curr_pid	      = { [0 ... MAX_CPUS - 1] = -1 },
		.sort_order	      = default_sort_order,
		.replay_repeat	      = 10,
		.profile_cpu	      = -1,
		.next_shortname1      = 'A',
		.next_shortname2      = '0',
		.select_list	      = LIST_HEAD_INIT(sched.select_list),
	};
	const struct option analyze_options[] = {
		OPT_END()
	};
	const struct option latency_options[] = {
	OPT_STRING('s', "sort", &sched.sort_order, "key[,key2...]",
		   "sort by key(s): runtime, switch, avg, max"),
	OPT_INCR('v', "verbose", &verbose,
		    "be more verbose (show symbol address, etc)"),
	OPT_INTEGER('C', "CPU", &sched.profile_cpu,
		    "CPU to profile on"),
	OPT_BOOLEAN('D', "dump-raw-trace", &dump_trace,
		    "dump raw trace in ASCII"),
	OPT_END()
	};
	const struct option replay_options[] = {
	OPT_UINTEGER('r', "repeat", &sched.replay_repeat,
		     "repeat the workload replay N times (-1: infinite)"),
	OPT_INCR('v', "verbose", &verbose,
		    "be more verbose (show symbol address, etc)"),
	OPT_BOOLEAN('D', "dump-raw-trace", &dump_trace,
		    "dump raw trace in ASCII"),
	OPT_END()
	};
	const struct option spr_replay_options[] = {
	OPT_CALLBACK('s', "select", &sched.select_list, "select",
		    "Number selects pid, name matches comm name",
		    parse_select_option),
	OPT_UINTEGER('r', "repeat", &sched.replay_repeat,
	            "repeat the workload replay N times (-1: infinite)"),
	OPT_INCR('v', "verbose", &verbose,
	            "be more verbose (show symbol address, etc)"),
	OPT_BOOLEAN('D', "dump-raw-trace", &dump_trace,
	            "dump raw trace in ASCII"),
	OPT_BOOLEAN('p', "preserve-time", &sched.preserve_time,
		    "Preserve time (do not erase sleeps while in running state)"),
	OPT_BOOLEAN('n', "dry-run", &sched.dry_run,
	            "do not execute"),
	OPT_INCR('d', "debug", &sched.debug,
	            "be more verbose"),
	OPT_BOOLEAN('g', "generate", &sched.generate,
	            "generate an spr program at stdout"),
	OPT_STRING('f', "spr-filename", &sched.spr_filename, "file",
	            "spr file name (instead of trace)"),
	OPT_BOOLEAN('l', "list", &sched.spr_list,
	            "list tasks & pids"),
	OPT_BOOLEAN('b', "bogoburn", &sched.bogoburn,
	            "burn time using a bogo-mips like busy loop"),
	OPT_U64('B', "bogoloops", &sched.bogoloops,
	            "set bogoloops value directly without re-calculating"),
	OPT_END()
	};
	const struct option sched_options[] = {
	OPT_STRING('i', "input", &sched.input_name, "file",
		    "input file name"),
	OPT_INCR('v', "verbose", &verbose,
		    "be more verbose (show symbol address, etc)"),
	OPT_BOOLEAN('D', "dump-raw-trace", &dump_trace,
		    "dump raw trace in ASCII"),
	OPT_END()
	};
	const char * const analyze_usage[] = {
		"perf sched analyze [<options>]",
		NULL
	};
	const char * const latency_usage[] = {
		"perf sched latency [<options>]",
		NULL
	};
	const char * const replay_usage[] = {
		"perf sched replay [<options>]",
		NULL
	};
	const char * const sched_usage[] = {
		"perf sched [<options>] {record|latency|map|replay|script|spr-replay}",
		NULL
	};
	static const char * const spr_replay_usage[] = {
		"perf sched spr-replay [<options>]",
		NULL
	};
	static struct trace_sched_handler analyze_ops  = {
		.runtime_event		= analyze_runtime_event,
	};
	struct trace_sched_handler lat_ops  = {
		.wakeup_event	    = latency_wakeup_event,
		.switch_event	    = latency_switch_event,
		.runtime_event	    = latency_runtime_event,
		.fork_event	    = latency_fork_event,
		.migrate_task_event = latency_migrate_task_event,
	};
	struct trace_sched_handler map_ops  = {
		.switch_event	    = map_switch_event,
	};
	struct trace_sched_handler replay_ops  = {
		.wakeup_event	    = replay_wakeup_event,
		.switch_event	    = replay_switch_event,
		.fork_event	    = replay_fork_event,
		.exit_event	    = replay_exit_event,
	};

	argc = parse_options(argc, argv, sched_options, sched_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);
	if (!argc)
		usage_with_options(sched_usage, sched_options);

	/*
	 * Aliased to 'perf script' for now:
	 */
	if (!strcmp(argv[0], "script"))
		return cmd_script(argc, argv, prefix);

	symbol__init();
	if (!strncmp(argv[0], "rec", 3)) {
		return __cmd_record(argc, argv);
	} else if (!strncmp(argv[0], "ana", 3)) {
		sched.tp_handler = &analyze_ops;
		if (argc) {
			argc = parse_options(argc, argv, analyze_options, analyze_usage, 0);
			if (argc)
				usage_with_options(analyze_usage, analyze_options);
		}
		return perf_sched__analyze(&sched);
	} else if (!strncmp(argv[0], "lat", 3)) {
		sched.tp_handler = &lat_ops;
		if (argc > 1) {
			argc = parse_options(argc, argv, latency_options, latency_usage, 0);
			if (argc)
				usage_with_options(latency_usage, latency_options);
		}
		setup_sorting(&sched, latency_options, latency_usage);
		return perf_sched__lat(&sched);
	} else if (!strcmp(argv[0], "map")) {
		sched.tp_handler = &map_ops;
		setup_sorting(&sched, latency_options, latency_usage);
		return perf_sched__map(&sched);
	} else if (!strncmp(argv[0], "rep", 3)) {
		sched.tp_handler = &replay_ops;
		if (argc) {
			argc = parse_options(argc, argv, replay_options, replay_usage, 0);
			if (argc)
				usage_with_options(replay_usage, replay_options);
		}
		return perf_sched__replay(&sched);
	} else if (!strncmp(argv[0], "spr-rep", 7)) {
		sched.tp_handler = &replay_ops;
		if (argc) {
			argc = parse_options(argc, argv, spr_replay_options, spr_replay_usage, 0);
			if (argc)
				usage_with_options(spr_replay_usage, spr_replay_options);
		}
		return perf_sched__spr_replay(&sched);
	} else {
		usage_with_options(sched_usage, sched_options);
	}

	return 0;
}
