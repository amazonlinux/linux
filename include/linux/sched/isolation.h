#ifndef _LINUX_SCHED_ISOLATION_H
#define _LINUX_SCHED_ISOLATION_H

#include <linux/cpumask.h>
#include <linux/cpuset.h>
#include <linux/init.h>
#include <linux/tick.h>

enum hk_type {
	HK_TYPE_DOMAIN,
	HK_TYPE_MANAGED_IRQ,
	HK_TYPE_KERNEL_NOISE,
	HK_TYPE_MAX,

	/*
	 * The following housekeeping types are only set by the nohz_full
	 * boot commandline option. So they can share the same value.
	 */
	HK_TYPE_TICK    = HK_TYPE_KERNEL_NOISE,
	HK_TYPE_TIMER   = HK_TYPE_KERNEL_NOISE,
	HK_TYPE_RCU     = HK_TYPE_KERNEL_NOISE,
	HK_TYPE_MISC    = HK_TYPE_KERNEL_NOISE,
	HK_TYPE_WQ      = HK_TYPE_KERNEL_NOISE,
	HK_TYPE_KTHREAD = HK_TYPE_KERNEL_NOISE
};

#ifdef CONFIG_CPU_ISOLATION
DECLARE_STATIC_KEY_FALSE(housekeeping_overridden);
extern int housekeeping_any_cpu(enum hk_type type);
extern const struct cpumask *housekeeping_cpumask(enum hk_type type);
extern bool housekeeping_enabled(enum hk_type type);
extern void housekeeping_affine(struct task_struct *t, enum hk_type type);
extern bool housekeeping_test_cpu(int cpu, enum hk_type type);
extern void __init housekeeping_init(void);

/*
 * Runtime scheduler CPU isolation.
 *
 * Allows kernel subsystems (e.g. the Nitro Enclaves driver) to mark a CPU
 * as scheduler-isolated at runtime: unbound workqueues stop targeting it,
 * and cpu_is_isolated() reports it as isolated, so callers that consult
 * that helper place their work elsewhere.  The CPU stays online and the
 * load balancer still sees it, because CFS domain membership follows
 * cpuset partitions and HK_TYPE_DOMAIN housekeeping, which this interface
 * does not touch.  Per-CPU kthreads continue to run, and tasks with hard
 * affinity set via sched_setaffinity() (e.g. pinned KVM vCPU threads)
 * continue to run.
 *
 * The isolation takes effect immediately on the 0 -> 1 refcount transition
 * and is removed on the 1 -> 0 transition.  The call is refcounted so it is
 * safe for multiple enclave/VM clients to claim overlapping CPUs.
 *
 * Returns 0 on success or a negative errno.  May sleep; must be called from
 * process context, not under cpus_read_lock().
 */
extern int sched_cpu_set_isolated(unsigned int cpu);
extern int sched_cpu_set_unisolated(unsigned int cpu);
extern bool sched_cpu_is_driver_isolated(int cpu);

#else

static inline int housekeeping_any_cpu(enum hk_type type)
{
	return smp_processor_id();
}

static inline const struct cpumask *housekeeping_cpumask(enum hk_type type)
{
	return cpu_possible_mask;
}

static inline bool housekeeping_enabled(enum hk_type type)
{
	return false;
}

static inline void housekeeping_affine(struct task_struct *t,
				       enum hk_type type) { }

static inline bool housekeeping_test_cpu(int cpu, enum hk_type type)
{
	return true;
}

static inline void housekeeping_init(void) { }

static inline int sched_cpu_set_isolated(unsigned int cpu) { return -ENOSYS; }
static inline int sched_cpu_set_unisolated(unsigned int cpu) { return -ENOSYS; }
static inline bool sched_cpu_is_driver_isolated(int cpu) { return false; }
#endif /* CONFIG_CPU_ISOLATION */

static inline bool housekeeping_cpu(int cpu, enum hk_type type)
{
#ifdef CONFIG_CPU_ISOLATION
	if (static_branch_unlikely(&housekeeping_overridden))
		return housekeeping_test_cpu(cpu, type);
#endif
	return true;
}

static inline bool cpu_is_isolated(int cpu)
{
	return !housekeeping_test_cpu(cpu, HK_TYPE_DOMAIN) ||
	       !housekeeping_test_cpu(cpu, HK_TYPE_TICK) ||
	       cpuset_cpu_is_isolated(cpu) ||
	       sched_cpu_is_driver_isolated(cpu);
}

#endif /* _LINUX_SCHED_ISOLATION_H */
