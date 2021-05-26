// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stack tracing support
 *
 * Copyright (C) 2012 ARM Ltd.
 */
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/stacktrace.h>
#include <linux/slab.h>

#include <asm/irq.h>
#include <asm/pointer_auth.h>
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
 * AArch64 PCS assigns the frame pointer to x29.
 *
 * A simple function prologue looks like this:
 * 	sub	sp, sp, #0x10
 *   	stp	x29, x30, [sp]
 *	mov	x29, sp
 *
 * A simple function epilogue looks like this:
 *	mov	sp, x29
 *	ldp	x29, x30, [sp]
 *	add	sp, sp, #0x10
 */


notrace void start_backtrace(struct stackframe *frame, unsigned long fp,
		     unsigned long pc)
{
	frame->fp = fp;
	frame->pc = pc;
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	frame->graph = 0;
#endif

	/*
	 * Prime the first unwind.
	 *
	 * In unwind_frame() we'll check that the FP points to a valid stack,
	 * which can't be STACK_TYPE_UNKNOWN, and the first unwind will be
	 * treated as a transition to whichever stack that happens to be. The
	 * prev_fp value won't be used, but we set it to 0 such that it is
	 * definitely not an accessible stack address.
	 */
	bitmap_zero(frame->stacks_done, __NR_STACK_TYPES);
	frame->prev_fp = 0;
	frame->prev_type = STACK_TYPE_UNKNOWN;
	frame->reliable = true;
}
NOKPROBE_SYMBOL(start_backtrace);

/*
 * Unwind from one frame record (A) to the next frame record (B).
 *
 * We terminate early if the location of B indicates a malformed chain of frame
 * records (e.g. a cycle), determined based on the location and fp value of A
 * and the location (but not the fp value) of B.
 */
int notrace unwind_frame(struct task_struct *tsk, struct stackframe *frame)
{
	unsigned long fp = frame->fp;
	struct stack_info info;

	frame->reliable = true;

	if (!tsk)
		tsk = current;

	if (fp & 0x7) {
		frame->reliable = false;
		return -EINVAL;
	}

	if (!on_accessible_stack(tsk, fp, 16, &info)) {
		frame->reliable = false;
		return -EINVAL;
	}

	if (test_bit(info.type, frame->stacks_done)) {
		frame->reliable = false;
		return -EINVAL;
	}

	/*
	 * As stacks grow downward, any valid record on the same stack must be
	 * at a strictly higher address than the prior record.
	 *
	 * Stacks can nest in several valid orders, e.g.
	 *
	 * TASK -> IRQ -> OVERFLOW -> SDEI_NORMAL
	 * TASK -> SDEI_NORMAL -> SDEI_CRITICAL -> OVERFLOW
	 *
	 * ... but the nesting itself is strict. Once we transition from one
	 * stack to another, it's never valid to unwind back to that first
	 * stack.
	 */
	if (info.type == frame->prev_type) {
		if (fp <= frame->prev_fp) {
			frame->reliable = false;
			return -EINVAL;
		}
	} else {
		set_bit(frame->prev_type, frame->stacks_done);
	}

	/*
	 * Record this frame record's values and location. The prev_fp and
	 * prev_type are only meaningful to the next unwind_frame() invocation.
	 */
	frame->fp = READ_ONCE_NOCHECK(*(unsigned long *)(fp));
	frame->pc = READ_ONCE_NOCHECK(*(unsigned long *)(fp + 8));
	frame->prev_fp = fp;
	frame->prev_type = info.type;

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (tsk->ret_stack &&
		(ptrauth_strip_insn_pac(frame->pc) == (unsigned long)return_to_handler)) {
		struct ftrace_ret_stack *ret_stack;
		/*
		 * This is a case where function graph tracer has
		 * modified a return address (LR) in a stack frame
		 * to hook a function return.
		 * So replace it to an original value.
		 */
		ret_stack = ftrace_graph_get_ret_stack(tsk, frame->graph++);
		if (WARN_ON_ONCE(!ret_stack)) {
			frame->reliable = false;
			return -EINVAL;
		}
		frame->pc = ret_stack->ret;
	}
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */

	frame->pc = ptrauth_strip_insn_pac(frame->pc);

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
	if (!__kernel_text_address(frame->pc)) {
		frame->reliable = false;
		return 0;
	}

	/*
	 * If the final frame has been reached, there is no more unwinding
	 * to do. There is no need to check if the return PC is considered
	 * unreliable by the unwinder.
	 */
	if (!frame->fp)
		return 0;

	/* Final frame; nothing to unwind */
	if (frame->fp == (unsigned long)task_pt_regs(tsk)->stackframe)
		return -ENOENT;

	if (unwinder_is_unreliable(frame->pc))
		frame->reliable = false;

	return 0;
}
NOKPROBE_SYMBOL(unwind_frame);

void notrace walk_stackframe(struct task_struct *tsk, struct stackframe *frame,
			     bool (*fn)(void *, unsigned long), void *data)
{
	while (1) {
		int ret;

		if (!fn(data, frame->pc))
			break;
		ret = unwind_frame(tsk, frame);
		if (ret < 0)
			break;
	}
}
NOKPROBE_SYMBOL(walk_stackframe);

static void dump_backtrace_entry(unsigned long where, const char *loglvl)
{
	printk("%s %pSb\n", loglvl, (void *)where);
}

void dump_backtrace(struct pt_regs *regs, struct task_struct *tsk,
		    const char *loglvl)
{
	struct stackframe frame;
	int skip = 0;

	pr_debug("%s(regs = %p tsk = %p)\n", __func__, regs, tsk);

	if (regs) {
		if (user_mode(regs))
			return;
		skip = 1;
	}

	if (!tsk)
		tsk = current;

	if (!try_get_task_stack(tsk))
		return;

	if (tsk == current) {
		start_backtrace(&frame,
				(unsigned long)__builtin_frame_address(0),
				(unsigned long)dump_backtrace);
	} else {
		/*
		 * task blocked in __switch_to
		 */
		start_backtrace(&frame,
				thread_saved_fp(tsk),
				thread_saved_pc(tsk));
	}

	printk("%sCall trace:\n", loglvl);
	do {
		/* skip until specified stack frame */
		if (!skip) {
			dump_backtrace_entry(frame.pc, loglvl);
		} else if (frame.fp == regs->regs[29]) {
			skip = 0;
			/*
			 * Mostly, this is the case where this function is
			 * called in panic/abort. As exception handler's
			 * stack frame does not contain the corresponding pc
			 * at which an exception has taken place, use regs->pc
			 * instead.
			 */
			dump_backtrace_entry(regs->pc, loglvl);
		}
	} while (!unwind_frame(tsk, &frame));

	put_task_stack(tsk);
}

void show_stack(struct task_struct *tsk, unsigned long *sp, const char *loglvl)
{
	dump_backtrace(NULL, tsk, loglvl);
	barrier();
}

#ifdef CONFIG_STACKTRACE

noinline notrace void arch_stack_walk(stack_trace_consume_fn consume_entry,
			      void *cookie, struct task_struct *task,
			      struct pt_regs *regs)
{
	struct stackframe frame;

	if (regs)
		start_backtrace(&frame, regs->regs[29], regs->pc);
	else if (task == current)
		start_backtrace(&frame,
				(unsigned long)__builtin_frame_address(1),
				(unsigned long)__builtin_return_address(0));
	else
		start_backtrace(&frame, thread_saved_fp(task),
				thread_saved_pc(task));

	walk_stackframe(task, &frame, consume_entry, cookie);
}

#endif
