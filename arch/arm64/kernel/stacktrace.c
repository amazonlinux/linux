// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stack tracing support
 *
 * Copyright (C) 2012 ARM Ltd.
 */
#include <linux/kernel.h>
#include <linux/efi.h>
#include <linux/export.h>
#include <linux/ftrace.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/stacktrace.h>
#include <linux/slab.h>

#include <asm/efi.h>
#include <asm/irq.h>
#include <asm/stack_pointer.h>
#include <asm/stacktrace.h>

struct code_range {
	unsigned long	start;
	unsigned long	end;
};

static struct code_range	*sym_code_functions;
static int			num_sym_code_functions;

int __init init_sym_code_functions(void)
{
	size_t size;

	size = (unsigned long)__sym_code_functions_end -
	       (unsigned long)__sym_code_functions_start;

	sym_code_functions = kmalloc(size, GFP_KERNEL);
	if (!sym_code_functions)
		return -ENOMEM;

	memcpy(sym_code_functions, __sym_code_functions_start, size);
	/* Update num_sym_code_functions after copying sym_code_functions. */
	smp_mb();
	num_sym_code_functions = size / sizeof(struct code_range);

	return 0;
}
early_initcall(init_sym_code_functions);

/*
 * Check the return PC against sym_code_functions[]. If there is a match, then
 * the consider the stack frame unreliable. These functions contain low-level
 * code where the frame pointer and/or the return address register cannot be
 * relied upon. This addresses the following situations:
 *
 *	- Exception handlers and entry assembly
 *	- Trampoline assembly (e.g., ftrace, kprobes)
 *	- Hypervisor-related assembly
 *	- Hibernation-related assembly
 *	- CPU start-stop, suspend-resume assembly
 *	- Kernel relocation assembly
 *
 * Some special cases covered by sym_code_functions[] deserve a mention here:
 *
 *	- All EL1 interrupt and exception stack traces will be considered
 *	  unreliable. This is the correct behavior as interrupts and exceptions
 *	  can happen on any instruction including ones in the frame pointer
 *	  prolog and epilog. Unless stack metadata is available so the unwinder
 *	  can unwind through these special cases, such stack traces will be
 *	  considered unreliable.
 *
 *	- A task can get preempted at the end of an interrupt. Stack traces
 *	  of preempted tasks will show the interrupt frame in the stack trace
 *	  and will be considered unreliable.
 *
 *	- Breakpoints are exceptions. So, all stack traces in the break point
 *	  handler (including probes) will be considered unreliable.
 *
 *	- All of the ftrace entry trampolines are considered unreliable. So,
 *	  all stack traces taken from tracer functions will be considered
 *	  unreliable.
 *
 *	- The Function Graph Tracer return trampoline (return_to_handler)
 *	  and the Kretprobe return trampoline (kretprobe_trampoline) are
 *	  also considered unreliable.
 *
 * Some of the special cases above can be unwound through using special logic
 * in unwind_frame().
 *
 *	- return_to_handler() is handled by the unwinder by attempting to
 *	  retrieve the original return address from the per-task return
 *	  address stack.
 *
 *	- kretprobe_trampoline() can be handled in a similar fashion by
 *	  attempting to retrieve the original return address from the per-task
 *	  kretprobe instance list.
 *
 *	- I reckon optprobes can be handled in a similar fashion in the future?
 *
 *	- Stack traces taken from the FTrace tracer functions can be handled
 *	  as well. ftrace_call is an inner label defined in the Ftrace entry
 *	  trampoline. This is the location where the call to a tracer function
 *	  is patched. So, if the return PC equals ftrace_call+4, it is
 *	  reliable. At that point, proper stack frames have already been set
 *	  up for the traced function and its caller.
 */
static bool unwinder_is_unreliable(unsigned long pc)
{
	const struct code_range *range;
	int i;

	/*
	 * If sym_code_functions[] were sorted, a binary search could be
	 * done to make this more performant.
	 */
	for (i = 0; i < num_sym_code_functions; i++) {
		range = &sym_code_functions[i];
		if (pc >= range->start && pc < range->end)
			return true;
	}

	return false;
}

/*
 * Start an unwind from a pt_regs.
 *
 * The unwind will begin at the PC within the regs.
 *
 * The regs must be on a stack currently owned by the calling task.
 */
static __always_inline void unwind_init_from_regs(struct unwind_state *state,
						  struct pt_regs *regs)
{
	unwind_init_common(state, current);

	state->fp = regs->regs[29];
	state->pc = regs->pc;
}

/*
 * Start an unwind from a caller.
 *
 * The unwind will begin at the caller of whichever function this is inlined
 * into.
 *
 * The function which invokes this must be noinline.
 */
static __always_inline void unwind_init_from_caller(struct unwind_state *state)
{
	unwind_init_common(state, current);

	state->fp = (unsigned long)__builtin_frame_address(1);
	state->pc = (unsigned long)__builtin_return_address(0);
}

/*
 * Start an unwind from a blocked task.
 *
 * The unwind will begin at the blocked tasks saved PC (i.e. the caller of
 * cpu_switch_to()).
 *
 * The caller should ensure the task is blocked in cpu_switch_to() for the
 * duration of the unwind, or the unwind will be bogus. It is never valid to
 * call this for the current task.
 */
static __always_inline void unwind_init_from_task(struct unwind_state *state,
						  struct task_struct *task)
{
	unwind_init_common(state, task);

	state->fp = thread_saved_fp(task);
	state->pc = thread_saved_pc(task);
}

/*
 * Unwind from one frame record (A) to the next frame record (B).
 *
 * We terminate early if the location of B indicates a malformed chain of frame
 * records (e.g. a cycle), determined based on the location and fp value of A
 * and the location (but not the fp value) of B.
 */
static int notrace unwind_next(struct unwind_state *state, int *reliable)
{
	struct task_struct *tsk = state->task;
	int err;

	err = unwind_next_frame_record(state);
	if (err) {
		if (reliable)
			*reliable = 0;
		return err;
	}

	state->pc = ptrauth_strip_insn_pac(state->pc);

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (tsk->ret_stack &&
		(state->pc == (unsigned long)return_to_handler)) {
		unsigned long orig_pc;
		/*
		 * This is a case where function graph tracer has
		 * modified a return address (LR) in a stack frame
		 * to hook a function return.
		 * So replace it to an original value.
		 */
		orig_pc = ftrace_graph_ret_addr(tsk, NULL, state->pc,
						(void *)state->fp);
		if (WARN_ON_ONCE(state->pc == orig_pc))
			return -EINVAL;
		state->pc = orig_pc;
	}
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */
#ifdef CONFIG_KRETPROBES
	if (is_kretprobe_trampoline(state->pc))
		state->pc = kretprobe_find_ret_addr(tsk, (void *)state->fp, &state->kr_cur);
#endif

	/*
	 * Check the return PC for conditions that make unwinding unreliable.
	 * In each case, mark the stack trace as such.
	 */

	/*
	 * Make sure that the return address is a proper kernel text address.
	 * A NULL or invalid return address could mean:
	 *
	 *	- generated code such as eBPF and optprobe trampolines
	 *	- Foreign code (e.g. EFI runtime services)
	 *	- Procedure Linkage Table (PLT) entries and veneer functions
	 */
	if (reliable && !__kernel_text_address(state->pc))
		*reliable = 0;

	/* Final frame; nothing to unwind */
	if (state->fp == (unsigned long)task_pt_regs(tsk)->stackframe)
		return -ENOENT;

	if (reliable && unwinder_is_unreliable(state->pc))
		*reliable = 0;

	return 0;
}
NOKPROBE_SYMBOL(unwind_next);

static void notrace unwind(struct unwind_state *state, int *reliable,
			   stack_trace_consume_fn consume_entry, void *cookie)
{
	while (1) {
		int ret;

		if (!consume_entry(cookie, state->pc))
			break;
		ret = unwind_next(state, reliable);
		if ((ret < 0) || (reliable && !(*reliable)))
			break;
	}
}
NOKPROBE_SYMBOL(unwind);

static bool dump_backtrace_entry(void *arg, unsigned long where)
{
	char *loglvl = arg;
	printk("%s %pSb\n", loglvl, (void *)where);
	return true;
}

void dump_backtrace(struct pt_regs *regs, struct task_struct *tsk,
		    const char *loglvl)
{
	pr_debug("%s(regs = %p tsk = %p)\n", __func__, regs, tsk);

	if (regs && user_mode(regs))
		return;

	if (!tsk)
		tsk = current;

	if (!try_get_task_stack(tsk))
		return;

	printk("%sCall trace:\n", loglvl);
	arch_stack_walk(dump_backtrace_entry, (void *)loglvl, tsk, regs);

	put_task_stack(tsk);
}

void show_stack(struct task_struct *tsk, unsigned long *sp, const char *loglvl)
{
	dump_backtrace(NULL, tsk, loglvl);
	barrier();
}

/*
 * Per-cpu stacks are only accessible when unwinding the current task in a
 * non-preemptible context.
 */
#define STACKINFO_CPU(name)					\
	({							\
		((task == current) && !preemptible())		\
			? stackinfo_get_##name()		\
			: stackinfo_get_unknown();		\
	})

/*
 * SDEI stacks are only accessible when unwinding the current task in an NMI
 * context.
 */
#define STACKINFO_SDEI(name)					\
	({							\
		((task == current) && in_nmi())			\
			? stackinfo_get_sdei_##name()		\
			: stackinfo_get_unknown();		\
	})

#define STACKINFO_EFI						\
	({							\
		((task == current) && current_in_efi())		\
			? stackinfo_get_efi()			\
			: stackinfo_get_unknown();		\
	})

noinline noinstr void arch_stack_walk(stack_trace_consume_fn consume_entry,
			      void *cookie, struct task_struct *task,
			      struct pt_regs *regs)
{
	struct stack_info stacks[] = {
		stackinfo_get_task(task),
		STACKINFO_CPU(irq),
#if defined(CONFIG_VMAP_STACK)
		STACKINFO_CPU(overflow),
#endif
#if defined(CONFIG_VMAP_STACK) && defined(CONFIG_ARM_SDE_INTERFACE)
		STACKINFO_SDEI(normal),
		STACKINFO_SDEI(critical),
#endif
#ifdef CONFIG_EFI
		STACKINFO_EFI,
#endif
	};
	struct unwind_state state = {
		.stacks = stacks,
		.nr_stacks = ARRAY_SIZE(stacks),
	};

	if (regs) {
		if (task != current)
			return;
		unwind_init_from_regs(&state, regs);
	} else if (task == current) {
		unwind_init_from_caller(&state);
	} else {
		unwind_init_from_task(&state, task);
	}

	unwind(&state, NULL, consume_entry, cookie);
}

/*
 * Walk the stack like arch_stack_walk() but stop the walk as soon as
 * some unreliability is detected in the stack.
 */
noinline noinstr int arch_stack_walk_reliable(
				stack_trace_consume_fn consume_entry,
				void *cookie, struct task_struct *task)
{
	struct stack_info stacks[] = {
		stackinfo_get_task(task),
		STACKINFO_CPU(irq),
#if defined(CONFIG_VMAP_STACK)
		STACKINFO_CPU(overflow),
#endif
#if defined(CONFIG_VMAP_STACK) && defined(CONFIG_ARM_SDE_INTERFACE)
		STACKINFO_SDEI(normal),
		STACKINFO_SDEI(critical),
#endif
#ifdef CONFIG_EFI
		STACKINFO_EFI,
#endif
	};
	struct unwind_state state = {
		.stacks = stacks,
		.nr_stacks = ARRAY_SIZE(stacks),
	};
	int reliable = 1;

	if (task == current) {
		unwind_init_from_caller(&state);
	} else {
		unwind_init_from_task(&state, task);
	}

	unwind(&state, &reliable, consume_entry, cookie);

	return reliable ? 0 : -EINVAL;
}
