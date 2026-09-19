// SPDX-License-Identifier: GPL-2.0-only
/*
 *
 * Copyright (C) 2013 Citrix Systems
 *
 * Author: Stefano Stabellini <stefano.stabellini@eu.citrix.com>
 */

#define pr_fmt(fmt) "arm-pv: " fmt

#include <linux/arm-smccc.h>
#include <linux/cpuhotplug.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/jump_label.h>
#include <linux/printk.h>
#include <linux/psci.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/static_call.h>

#include <asm/paravirt.h>
#include <asm/pvclock-abi.h>
#include <asm/smp_plat.h>

struct static_key paravirt_steal_enabled;
struct static_key paravirt_guest_clock_enabled;
struct static_key paravirt_steal_rq_enabled;

static u64 native_steal_clock(int cpu)
{
	return 0;
}

/*
 * Default for pv_guest_clock when no paravirt provider implements
 * publishing cpu_guest_time.  Hosts without KVM_CAP_NO_STEAL_TIME use
 * this and the /proc/stat relabel is a no-op.
 */
static u64 native_guest_clock(int cpu)
{
	return 0;
}

DEFINE_STATIC_CALL(pv_steal_clock, native_steal_clock);
DEFINE_STATIC_CALL(pv_guest_clock, native_guest_clock);

struct pv_time_stolen_time_region {
	struct pvclock_vcpu_stolen_time __rcu *kaddr;
};

static DEFINE_PER_CPU(struct pv_time_stolen_time_region, stolen_time_region);

static bool steal_acc = true;
static int __init parse_no_stealacc(char *arg)
{
	steal_acc = false;
	return 0;
}

early_param("no-steal-acc", parse_no_stealacc);

/* return stolen time in ns by asking the hypervisor */
static u64 para_steal_clock(int cpu)
{
	struct pvclock_vcpu_stolen_time *kaddr = NULL;
	struct pv_time_stolen_time_region *reg;
	u64 ret = 0;

	reg = per_cpu_ptr(&stolen_time_region, cpu);

	/*
	 * paravirt_steal_clock() may be called before the CPU
	 * online notification callback runs. Until the callback
	 * has run we just return zero.
	 */
	rcu_read_lock();
	kaddr = rcu_dereference(reg->kaddr);
	if (!kaddr) {
		rcu_read_unlock();
		return 0;
	}

	ret = le64_to_cpu(READ_ONCE(kaddr->stolen_time));
	rcu_read_unlock();
	return ret;
}

/*
 * Cumulative ns of host-observed "parent vCPU was not on a pCPU" time
 * for the given vCPU, published by the host via the .cpu_guest_time
 * field of the per-CPU stolen_time region.  Valid only when
 * PVCLOCK_STOLEN_TIME_GUEST is set in .attributes; returns 0 otherwise
 * so /proc/stat takes the conventional path that reads idle from the
 * NO_HZ accumulator.
 */
static u64 para_guest_clock(int cpu)
{
	struct pvclock_vcpu_stolen_time *kaddr = NULL;
	struct pv_time_stolen_time_region *reg;
	u64 ret = 0;
	u32 attrs;

	reg = per_cpu_ptr(&stolen_time_region, cpu);

	rcu_read_lock();
	kaddr = rcu_dereference(reg->kaddr);
	if (!kaddr) {
		rcu_read_unlock();
		return 0;
	}

	attrs = le32_to_cpu(READ_ONCE(kaddr->attributes));
	if (!(attrs & PVCLOCK_STOLEN_TIME_GUEST)) {
		rcu_read_unlock();
		return 0;
	}

	ret = le64_to_cpu(READ_ONCE(kaddr->cpu_guest_time));
	rcu_read_unlock();
	return ret;
}

static int stolen_time_cpu_down_prepare(unsigned int cpu)
{
	struct pvclock_vcpu_stolen_time *kaddr = NULL;
	struct pv_time_stolen_time_region *reg;

	reg = this_cpu_ptr(&stolen_time_region);
	if (!reg->kaddr)
		return 0;

	kaddr = rcu_replace_pointer(reg->kaddr, NULL, true);
	synchronize_rcu();
	memunmap(kaddr);

	return 0;
}

static int stolen_time_cpu_online(unsigned int cpu)
{
	struct pvclock_vcpu_stolen_time *kaddr = NULL;
	struct pv_time_stolen_time_region *reg;
	struct arm_smccc_res res;

	reg = this_cpu_ptr(&stolen_time_region);

	arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_TIME_ST, &res);

	if (res.a0 == SMCCC_RET_NOT_SUPPORTED)
		return -EINVAL;

	kaddr = memremap(res.a0,
			      sizeof(struct pvclock_vcpu_stolen_time),
			      MEMREMAP_WB);

	rcu_assign_pointer(reg->kaddr, kaddr);

	if (!reg->kaddr) {
		pr_warn("Failed to map stolen time data structure\n");
		return -ENOMEM;
	}

	/*
	 * Reject an unknown revision, and any attribute bit this kernel
	 * cannot interpret.  Known bits are accepted: a host that sets
	 * PVCLOCK_STOLEN_TIME_GUEST must not lose steal time.
	 */
	if (le32_to_cpu(kaddr->revision) != 0 ||
	    (le32_to_cpu(kaddr->attributes) &
	     ~PVCLOCK_STOLEN_TIME_ATTRS_SUPPORTED)) {
		pr_warn_once("Unexpected revision or attributes in stolen time data\n");
		return -ENXIO;
	}

	return 0;
}

static int __init pv_time_init_stolen_time(void)
{
	int ret;

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
				"hypervisor/arm/pvtime:online",
				stolen_time_cpu_online,
				stolen_time_cpu_down_prepare);
	if (ret < 0)
		return ret;
	return 0;
}

/*
 * Whether the host advertises the guest-time extension on the boot CPU.
 * Called from pv_time_init() after cpuhp_setup_state() has run the online
 * callback for this CPU, never from the callback itself: enabling the
 * static key needs static_key_slow_inc(), which takes cpus_read_lock()
 * (kernel/jump_label.c), and CPU hotplug holds that lock for write.
 */
static bool __init has_pv_guest_clock(void)
{
	struct pvclock_vcpu_stolen_time *kaddr;
	bool ret = false;

	rcu_read_lock();
	kaddr = rcu_dereference(this_cpu_ptr(&stolen_time_region)->kaddr);
	if (kaddr)
		ret = !!(le32_to_cpu(READ_ONCE(kaddr->attributes)) &
			 PVCLOCK_STOLEN_TIME_GUEST);
	rcu_read_unlock();

	return ret;
}

static bool __init has_pv_steal_clock(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(ARM_SMCCC_ARCH_FEATURES_FUNC_ID,
			     ARM_SMCCC_HV_PV_TIME_FEATURES, &res);

	if (res.a0 != SMCCC_RET_SUCCESS)
		return false;

	arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_TIME_FEATURES,
			     ARM_SMCCC_HV_PV_TIME_ST, &res);

	return (res.a0 == SMCCC_RET_SUCCESS);
}

int __init pv_time_init(void)
{
	int ret;

	if (!has_pv_steal_clock())
		return 0;

	ret = pv_time_init_stolen_time();
	if (ret)
		return ret;

	static_call_update(pv_steal_clock, para_steal_clock);

	static_key_slow_inc(&paravirt_steal_enabled);

	/*
	 * Only reinterpret suppressed steal time as guest time when the
	 * host says it publishes .cpu_guest_time.  Leaving the static key
	 * off keeps account_guest_time() on its conventional path for
	 * every other host.
	 */
	if (has_pv_guest_clock()) {
		static_call_update(pv_guest_clock, para_guest_clock);
		static_key_enable(&paravirt_guest_clock_enabled);
	}
	if (steal_acc)
		static_key_slow_inc(&paravirt_steal_rq_enabled);

	pr_info("using stolen time PV\n");

	return 0;
}
