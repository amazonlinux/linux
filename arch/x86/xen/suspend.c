// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/tick.h>
#include <linux/percpu-defs.h>
#include <linux/syscore_ops.h>
#include <linux/kernel_stat.h>

#include <xen/xen.h>
#include <xen/interface/xen.h>
#include <xen/interface/memory.h>
#include <xen/grant_table.h>
#include <xen/events.h>
#include <xen/xen-ops.h>

#include <asm/cpufeatures.h>
#include <asm/msr-index.h>
#include <asm/xen/hypercall.h>
#include <asm/xen/page.h>
#include <asm/fixmap.h>
#include <asm/pvclock.h>

#include "xen-ops.h"
#include "mmu.h"
#include "pmu.h"

static DEFINE_PER_CPU(u64, spec_ctrl);

void xen_arch_pre_suspend(void)
{
	xen_save_time_memory_area();

	if (xen_pv_domain())
		xen_pv_pre_suspend();
}

void xen_arch_post_suspend(int cancelled)
{
	if (xen_pv_domain())
		xen_pv_post_suspend(cancelled);
	else
		xen_hvm_post_suspend(cancelled);

	xen_restore_time_memory_area();
}

static void xen_vcpu_notify_restore(void *data)
{
	if (xen_pv_domain() && boot_cpu_has(X86_FEATURE_SPEC_CTRL))
		wrmsrl(MSR_IA32_SPEC_CTRL, this_cpu_read(spec_ctrl));

	/* Boot processor notified via generic timekeeping_resume() */
	if (smp_processor_id() == 0)
		return;

	tick_resume_local();
}

static void xen_vcpu_notify_suspend(void *data)
{
	u64 tmp;

	tick_suspend_local();

	if (xen_pv_domain() && boot_cpu_has(X86_FEATURE_SPEC_CTRL)) {
		rdmsrl(MSR_IA32_SPEC_CTRL, tmp);
		this_cpu_write(spec_ctrl, tmp);
		wrmsrl(MSR_IA32_SPEC_CTRL, 0);
	}
}

void xen_arch_resume(void)
{
	int cpu;

	on_each_cpu(xen_vcpu_notify_restore, NULL, 1);

	for_each_online_cpu(cpu)
		xen_pmu_init(cpu);
}

void xen_arch_suspend(void)
{
	int cpu;

	for_each_online_cpu(cpu)
		xen_pmu_finish(cpu);

	on_each_cpu(xen_vcpu_notify_suspend, NULL, 1);
}

static int xen_syscore_suspend(void)
{
	struct xen_remove_from_physmap xrfp;
	int cpu, ret;

	/* Xen suspend does similar stuffs in its own logic */
	if (xen_suspend_mode_is_xen_suspend())
		return 0;

	for_each_present_cpu(cpu) {
		/*
		 * Nonboot CPUs are already offline, but the last copy of
		 * runstate info is still accessible.
		 */
		xen_save_steal_clock(cpu);
	}

	xen_shutdown_pirqs();

	xrfp.domid = DOMID_SELF;
	xrfp.gpfn = __pa(HYPERVISOR_shared_info) >> PAGE_SHIFT;

	ret = HYPERVISOR_memory_op(XENMEM_remove_from_physmap, &xrfp);
	if (!ret)
		HYPERVISOR_shared_info = &xen_dummy_shared_info;

	return ret;
}

static void xen_syscore_resume(void)
{
	/* Xen suspend does similar stuffs in its own logic */
	if (xen_suspend_mode_is_xen_suspend())
		return;

	/* No need to setup vcpu_info as it's already moved off */
	xen_hvm_map_shared_info();

	pvclock_resume();

	/* Nonboot CPUs will be resumed when they're brought up */
	xen_restore_steal_clock(smp_processor_id());

	gnttab_resume();

	xen_restore_pirqs();
}

/*
 * These callbacks will be called with interrupts disabled and when having only
 * one CPU online.
 */
static struct syscore_ops xen_hvm_syscore_ops = {
	.suspend = xen_syscore_suspend,
	.resume = xen_syscore_resume
};

void __init xen_setup_syscore_ops(void)
{
	if (xen_hvm_domain())
		register_syscore_ops(&xen_hvm_syscore_ops);
}
