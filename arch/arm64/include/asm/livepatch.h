/* SPDX-License-Identifier: GPL-2.0
 *
 * livepatch.h - arm64-specific Kernel Live Patching Core
 */
#ifndef _ASM_ARM64_LIVEPATCH_H
#define _ASM_ARM64_LIVEPATCH_H

#include <linux/ftrace.h>

static inline void klp_arch_set_pc(struct pt_regs *regs, unsigned long ip)
{
	regs->pc = ip;
}

/*
 * klp_get_ftrace_location is expected to return the address of the BL to the
 * relevant ftrace handler in the callsite. The location of this can vary based
 * on several compilation options.
 * CONFIG_DYNAMIC_FTRACE_WITH_REGS
 *	- Inserts 2 nops on function entry the second of which is the BL
 *	  referenced above. (See ftrace_init_nop() for the callsite sequence)
 *	  (this is required by livepatch and must be selected)
 * CONFIG_ARM64_BTI_KERNEL:
 *	- Inserts a hint(BTI C) on function entry if the function is called
 *	  indirectly (to satisfy BTI requirements), which is inserted before
 *	  the two nops from above.
 */
#define klp_get_ftrace_location klp_get_ftrace_location
static inline unsigned long klp_get_ftrace_location(unsigned long faddr)
{
	unsigned long addr = faddr + AARCH64_INSN_SIZE;

#if IS_ENABLED(CONFIG_ARM64_BTI_KERNEL)
	addr = ftrace_location_range(addr, addr + AARCH64_INSN_SIZE);
#endif

	return addr;
}

#endif /* _ASM_ARM64_LIVEPATCH_H */
