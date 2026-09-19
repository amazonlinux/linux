// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Housekeeping management. Manage the targets for routine code that can run on
 *  any CPU: unbound workqueues, timers, kthreads and any offloadable work.
 *
 * Copyright (C) 2017 Red Hat, Inc., Frederic Weisbecker
 * Copyright (C) 2017-2018 SUSE, Frederic Weisbecker
 *
 */
#include <linux/sched/isolation.h>
#include "sched.h"

enum hk_flags {
	HK_FLAG_DOMAIN		= BIT(HK_TYPE_DOMAIN),
	HK_FLAG_MANAGED_IRQ	= BIT(HK_TYPE_MANAGED_IRQ),
	HK_FLAG_KERNEL_NOISE	= BIT(HK_TYPE_KERNEL_NOISE),
};

DEFINE_STATIC_KEY_FALSE(housekeeping_overridden);
EXPORT_SYMBOL_GPL(housekeeping_overridden);

struct housekeeping {
	cpumask_var_t cpumasks[HK_TYPE_MAX];
	unsigned long flags;
};

static struct housekeeping housekeeping;

bool housekeeping_enabled(enum hk_type type)
{
	return !!(housekeeping.flags & BIT(type));
}
EXPORT_SYMBOL_GPL(housekeeping_enabled);

int housekeeping_any_cpu(enum hk_type type)
{
	int cpu;

	if (static_branch_unlikely(&housekeeping_overridden)) {
		if (housekeeping.flags & BIT(type)) {
			cpu = sched_numa_find_closest(housekeeping.cpumasks[type], smp_processor_id());
			if (cpu < nr_cpu_ids)
				return cpu;

			cpu = cpumask_any_and_distribute(housekeeping.cpumasks[type], cpu_online_mask);
			if (likely(cpu < nr_cpu_ids))
				return cpu;
			/*
			 * Unless we have another problem this can only happen
			 * at boot time before start_secondary() brings the 1st
			 * housekeeping CPU up.
			 */
			WARN_ON_ONCE(system_state == SYSTEM_RUNNING ||
				     type != HK_TYPE_TIMER);
		}
	}
	return smp_processor_id();
}
EXPORT_SYMBOL_GPL(housekeeping_any_cpu);

const struct cpumask *housekeeping_cpumask(enum hk_type type)
{
	if (static_branch_unlikely(&housekeeping_overridden))
		if (housekeeping.flags & BIT(type))
			return housekeeping.cpumasks[type];
	return cpu_possible_mask;
}
EXPORT_SYMBOL_GPL(housekeeping_cpumask);

void housekeeping_affine(struct task_struct *t, enum hk_type type)
{
	if (static_branch_unlikely(&housekeeping_overridden))
		if (housekeeping.flags & BIT(type))
			set_cpus_allowed_ptr(t, housekeeping.cpumasks[type]);
}
EXPORT_SYMBOL_GPL(housekeeping_affine);

bool housekeeping_test_cpu(int cpu, enum hk_type type)
{
	if (static_branch_unlikely(&housekeeping_overridden))
		if (housekeeping.flags & BIT(type))
			return cpumask_test_cpu(cpu, housekeeping.cpumasks[type]);
	return true;
}
EXPORT_SYMBOL_GPL(housekeeping_test_cpu);

void __init housekeeping_init(void)
{
	enum hk_type type;

	if (!housekeeping.flags)
		return;

	static_branch_enable(&housekeeping_overridden);

	if (housekeeping.flags & HK_FLAG_KERNEL_NOISE)
		sched_tick_offload_init();

	for_each_set_bit(type, &housekeeping.flags, HK_TYPE_MAX) {
		/* We need at least one CPU to handle housekeeping work */
		WARN_ON_ONCE(cpumask_empty(housekeeping.cpumasks[type]));
	}
}

static void __init housekeeping_setup_type(enum hk_type type,
					   cpumask_var_t housekeeping_staging)
{

	alloc_bootmem_cpumask_var(&housekeeping.cpumasks[type]);
	cpumask_copy(housekeeping.cpumasks[type],
		     housekeeping_staging);
}

static int __init housekeeping_setup(char *str, unsigned long flags)
{
	cpumask_var_t non_housekeeping_mask, housekeeping_staging;
	unsigned int first_cpu;
	int err = 0;

	if ((flags & HK_FLAG_KERNEL_NOISE) && !(housekeeping.flags & HK_FLAG_KERNEL_NOISE)) {
		if (!IS_ENABLED(CONFIG_NO_HZ_FULL)) {
			pr_warn("Housekeeping: nohz unsupported."
				" Build with CONFIG_NO_HZ_FULL\n");
			return 0;
		}
	}

	alloc_bootmem_cpumask_var(&non_housekeeping_mask);
	if (cpulist_parse(str, non_housekeeping_mask) < 0) {
		pr_warn("Housekeeping: nohz_full= or isolcpus= incorrect CPU range\n");
		goto free_non_housekeeping_mask;
	}

	alloc_bootmem_cpumask_var(&housekeeping_staging);
	cpumask_andnot(housekeeping_staging,
		       cpu_possible_mask, non_housekeeping_mask);

	first_cpu = cpumask_first_and(cpu_present_mask, housekeeping_staging);
	if (first_cpu >= nr_cpu_ids || first_cpu >= setup_max_cpus) {
		__cpumask_set_cpu(smp_processor_id(), housekeeping_staging);
		__cpumask_clear_cpu(smp_processor_id(), non_housekeeping_mask);
		if (!housekeeping.flags) {
			pr_warn("Housekeeping: must include one present CPU, "
				"using boot CPU:%d\n", smp_processor_id());
		}
	}

	if (cpumask_empty(non_housekeeping_mask))
		goto free_housekeeping_staging;

	if (!housekeeping.flags) {
		/* First setup call ("nohz_full=" or "isolcpus=") */
		enum hk_type type;

		for_each_set_bit(type, &flags, HK_TYPE_MAX)
			housekeeping_setup_type(type, housekeeping_staging);
	} else {
		/* Second setup call ("nohz_full=" after "isolcpus=" or the reverse) */
		enum hk_type type;
		unsigned long iter_flags = flags & housekeeping.flags;

		for_each_set_bit(type, &iter_flags, HK_TYPE_MAX) {
			if (!cpumask_equal(housekeeping_staging,
					   housekeeping.cpumasks[type])) {
				pr_warn("Housekeeping: nohz_full= must match isolcpus=\n");
				goto free_housekeeping_staging;
			}
		}

		iter_flags = flags & ~housekeeping.flags;

		for_each_set_bit(type, &iter_flags, HK_TYPE_MAX)
			housekeeping_setup_type(type, housekeeping_staging);
	}

	if ((flags & HK_FLAG_KERNEL_NOISE) && !(housekeeping.flags & HK_FLAG_KERNEL_NOISE))
		tick_nohz_full_setup(non_housekeeping_mask);

	housekeeping.flags |= flags;
	err = 1;

free_housekeeping_staging:
	free_bootmem_cpumask_var(housekeeping_staging);
free_non_housekeeping_mask:
	free_bootmem_cpumask_var(non_housekeeping_mask);

	return err;
}

static int __init housekeeping_nohz_full_setup(char *str)
{
	unsigned long flags;

	flags = HK_FLAG_KERNEL_NOISE;

	return housekeeping_setup(str, flags);
}
__setup("nohz_full=", housekeeping_nohz_full_setup);

static int __init housekeeping_isolcpus_setup(char *str)
{
	unsigned long flags = 0;
	bool illegal = false;
	char *par;
	int len;

	while (isalpha(*str)) {
		/*
		 * isolcpus=nohz is equivalent to nohz_full.
		 */
		if (!strncmp(str, "nohz,", 5)) {
			str += 5;
			flags |= HK_FLAG_KERNEL_NOISE;
			continue;
		}

		if (!strncmp(str, "domain,", 7)) {
			str += 7;
			flags |= HK_FLAG_DOMAIN;
			continue;
		}

		if (!strncmp(str, "managed_irq,", 12)) {
			str += 12;
			flags |= HK_FLAG_MANAGED_IRQ;
			continue;
		}

		/*
		 * Skip unknown sub-parameter and validate that it is not
		 * containing an invalid character.
		 */
		for (par = str, len = 0; *str && *str != ','; str++, len++) {
			if (!isalpha(*str) && *str != '_')
				illegal = true;
		}

		if (illegal) {
			pr_warn("isolcpus: Invalid flag %.*s\n", len, par);
			return 0;
		}

		pr_info("isolcpus: Skipped unknown flag %.*s\n", len, par);
		str++;
	}

	/* Default behaviour for isolcpus without flags */
	if (!flags)
		flags |= HK_FLAG_DOMAIN;

	return housekeeping_setup(str, flags);
}
__setup("isolcpus=", housekeeping_isolcpus_setup);

/*
 * Runtime scheduler CPU isolation
 * ================================
 *
 * Lets in-kernel subsystems (notably the Nitro Enclaves driver when running
 * in ne_cpus=dynamic mode) park individual CPUs at runtime: unbound
 * workqueues stop targeting the CPU, and cpu_is_isolated() starts reporting
 * it as isolated, so callers that consult that helper place their work
 * elsewhere.  None of it takes the CPU offline.
 *
 * The isolated state reuses the state machine that cpuset PRS_ISOLATED
 * partitions drive, but is reachable from a kernel module via a narrow
 * function-call API instead of through cgroupfs.  It is weaker than a cpuset
 * partition: CFS domain membership follows cpuset partitions and
 * HK_TYPE_DOMAIN housekeeping, so the load balancer still sees the CPU, and
 * this kernel has no interface for dropping a CPU from the timer-migration
 * hierarchy.  Per-CPU kthreads (migration/N, ksoftirqd/N, rcu_* ...) continue
 * to run on the isolated CPU, as do tasks that pinned themselves there with
 * sched_setaffinity() (e.g. pinned KVM vCPU threads).  That is what the
 * Nitro Enclaves dynamic CPU pool wants: the qemu vCPU threads own the CPU
 * once pinned, and unbound parent-side work lands elsewhere.
 *
 * Concurrency: updates are serialized by driver_isolated_mutex.  Lookups
 * via cpu_is_isolated() are lockless and may briefly observe a stale bit
 * during an in-flight transition; this is the same guarantee the
 * cpuset-isolated path provides.  Its consumers (block-queue mapping,
 * per-CPU LRU and vmstat deferral, memcg stock draining) only decide where
 * to put work, so a stale read costs at most one misplaced item.
 *
 * Composition with cpuset partitions is not yet supported: a CPU that is a
 * member of an isolated cpuset partition AND of the driver-isolated set
 * will be unisolated when either set releases it, because each subsystem
 * passes its own exclude mask to the unbound-workqueue machinery, which
 * takes the last write.  The Nitro Enclaves use case does not mix the two,
 * so leave the generalization (a single "effective isolated" mask jointly
 * managed by cpuset and drivers) to a follow-up.
 */

#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/cpuset.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

static DEFINE_MUTEX(driver_isolated_mutex);
static cpumask_var_t driver_isolated_cpus;
/*
 * Per-CPU refcount.  A CPU is isolated while its refcount > 0.  We cap at
 * u16 because the only current user is the NE driver (one refcount per
 * enclave-vCPU); a realistic upper bound is a few hundred per CPU.
 */
static u16 driver_isolated_refcnt[NR_CPUS];
static bool driver_isolated_ready;

static int __init sched_driver_isolation_init(void)
{
	if (!zalloc_cpumask_var(&driver_isolated_cpus, GFP_KERNEL))
		return -ENOMEM;
	driver_isolated_ready = true;
	return 0;
}
core_initcall(sched_driver_isolation_init);

bool sched_cpu_is_driver_isolated(int cpu)
{
	if (!driver_isolated_ready)
		return false;
	return cpumask_test_cpu(cpu, driver_isolated_cpus);
}
EXPORT_SYMBOL_GPL(sched_cpu_is_driver_isolated);

/*
 * Apply the current driver_isolated_cpus mask to the scheduler and unbound
 * workqueue exclusion.  Must be called with driver_isolated_mutex held and
 * cpus_read_lock() held.
 */
static int driver_isolation_apply(void)
{
	int ret;

	lockdep_assert_cpus_held();

	/*
	 * workqueue_unbound_exclude_cpumask() takes the full exclude set as
	 * input; it internally diffs against the last-applied set.  The
	 * cpumask we pass in persists across the call.
	 *
	 * Note: v6.19+ also has tmigr_isolated_exclude_cpumask() to remove
	 * the isolated CPUs from the timer-migration hierarchy.  That API
	 * does not exist on v6.18; timer migration will still target driver-
	 * isolated CPUs, which affects idle wakeups but not the
	 * unbound-workqueue exclusion and cpu_is_isolated() marking that NE
	 * vCPU isolation relies on.
	 */
	ret = workqueue_unbound_exclude_cpumask(driver_isolated_cpus);
	if (ret)
		return ret;

	/*
	 * rebuild_sched_domains_cpuslocked() is not exported; use the
	 * public rebuild_sched_domains() wrapper which takes its own locks.
	 * We already hold cpus_read_lock() but that wrapper takes
	 * cpus_read_lock() again; it is recursive (rwsem) and fine.
	 */
	rebuild_sched_domains();
	return 0;
}

int sched_cpu_set_isolated(unsigned int cpu)
{
	int ret;

	if (cpu >= nr_cpu_ids)
		return -EINVAL;
	if (!driver_isolated_ready)
		return -EAGAIN;

	cpus_read_lock();
	mutex_lock(&driver_isolated_mutex);

	if (driver_isolated_refcnt[cpu] == U16_MAX) {
		ret = -ERANGE;
		goto out;
	}

	if (driver_isolated_refcnt[cpu]++ != 0) {
		/* Already isolated; just bumped the refcount. */
		ret = 0;
		goto out;
	}

	cpumask_set_cpu(cpu, driver_isolated_cpus);
	ret = driver_isolation_apply();
	if (ret) {
		cpumask_clear_cpu(cpu, driver_isolated_cpus);
		driver_isolated_refcnt[cpu] = 0;
	}
out:
	mutex_unlock(&driver_isolated_mutex);
	cpus_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(sched_cpu_set_isolated);

int sched_cpu_set_unisolated(unsigned int cpu)
{
	int ret;

	if (cpu >= nr_cpu_ids)
		return -EINVAL;
	if (!driver_isolated_ready)
		return -EAGAIN;

	cpus_read_lock();
	mutex_lock(&driver_isolated_mutex);

	if (driver_isolated_refcnt[cpu] == 0) {
		ret = -EINVAL;
		goto out;
	}

	if (--driver_isolated_refcnt[cpu] != 0) {
		/* Still held by another caller. */
		ret = 0;
		goto out;
	}

	cpumask_clear_cpu(cpu, driver_isolated_cpus);
	ret = driver_isolation_apply();
	if (ret) {
		/* Rollback: put the bit back and restore the refcount. */
		cpumask_set_cpu(cpu, driver_isolated_cpus);
		driver_isolated_refcnt[cpu] = 1;
	}
out:
	mutex_unlock(&driver_isolated_mutex);
	cpus_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(sched_cpu_set_unisolated);
