/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_PARAVIRT_H
#define _ASM_ARM64_PARAVIRT_H

#ifdef CONFIG_PARAVIRT
#include <linux/static_call_types.h>

struct static_key;
extern struct static_key paravirt_steal_enabled;
extern struct static_key paravirt_steal_rq_enabled;

u64 dummy_steal_clock(int cpu);
u64 dummy_guest_clock(int cpu);

DECLARE_STATIC_CALL(pv_steal_clock, dummy_steal_clock);
DECLARE_STATIC_CALL(pv_guest_clock, dummy_guest_clock);

extern struct static_key paravirt_guest_clock_enabled;

static inline u64 paravirt_steal_clock(int cpu)
{
	return static_call(pv_steal_clock)(cpu);
}

/*
 * Cumulative ns of host-observed "parent vCPU was not on a pCPU" time
 * for the given vCPU, published by the host via the .cpu_guest_time
 * field of struct pvclock_vcpu_stolen_time when KVM_CAP_NO_STEAL_TIME
 * is in effect.  This is the sum of run_delay (parent runnable but
 * waiting) and HLT (parent voluntarily yielded), i.e. the host-side
 * view of the parent's idle time.  Returns 0 on hosts that don't
 * advertise the cap (the dummy callback is a no-op), so /proc/stat
 * takes the conventional path.
 *
 * The /proc/stat read path moves this cumulative value from the idle
 * column into the guest column, so that customer-visible accounting
 * reflects that the parent's spare CPU budget was available to its
 * sibling VMs (Nitro Enclaves).
 */
static inline u64 paravirt_guest_clock(int cpu)
{
	return static_call(pv_guest_clock)(cpu);
}

int __init pv_time_init(void);

#else

#define pv_time_init() do {} while (0)

#endif // CONFIG_PARAVIRT

#endif
