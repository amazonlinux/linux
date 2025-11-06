/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTO_FIPS140_FN_REDIRECT_H
#define _CRYPTO_FIPS140_FN_REDIRECT_H

/*
 * Function redirect macro for --wrap symbols.
 *
 * Each __wrap_<sym> is a naked function that tail-jumps through
 * __fips140_fn_ptr_<sym>. The pointer is populated by fips140.ko
 * at module load time (during early init) via do_crypto_fn().
 *
 * Before population, points to __fips140_fn_not_redirected (panic).
 *
 * The function pointer is marked __ro_after_init so that it is
 * writable during early init when fips140.ko loads, but becomes
 * read-only after mark_rodata_ro() runs. This prevents any later
 * modification of the redirect targets.
 */

#include <linux/linkage.h>
#include <linux/export.h>
#include <linux/cache.h>

extern void __fips140_fn_not_redirected(void);

#ifdef CONFIG_X86_64

#define DEFINE_CRYPTO_FN_REDIRECT(sym)						\
	void *__fips140_fn_ptr_##sym __ro_after_init = (void *)__fips140_fn_not_redirected; \
	EXPORT_SYMBOL_GPL(__fips140_fn_ptr_##sym);				\
	void __wrap_##sym(void);					\
	__attribute__((naked)) void __wrap_##sym(void)			\
	{								\
		asm volatile(						\
			"movq __fips140_fn_ptr_" #sym "(%%rip), %%rax\n\t"	\
			"jmp __x86_indirect_thunk_rax\n\t"		\
			::: "rax", "memory"				\
		);							\
		__builtin_unreachable();					\
	}

#elif defined(CONFIG_ARM64)

#define DEFINE_CRYPTO_FN_REDIRECT(sym)						\
	void *__fips140_fn_ptr_##sym __ro_after_init = (void *)__fips140_fn_not_redirected; \
	EXPORT_SYMBOL_GPL(__fips140_fn_ptr_##sym);				\
	void __wrap_##sym(void);					\
	__attribute__((naked)) void __wrap_##sym(void)			\
	{								\
		asm volatile(						\
			"adrp x16, __fips140_fn_ptr_" #sym "\n\t"		\
			"ldr  x16, [x16, :lo12:__fips140_fn_ptr_" #sym "]\n\t" \
			"br   x16\n\t"					\
			::: "x16", "memory"				\
		);							\
		__builtin_unreachable();					\
	}

#else
#error "FIPS140 function redirect trampolines not implemented for this architecture"
#endif

#endif /* _CRYPTO_FIPS140_FN_REDIRECT_H */
