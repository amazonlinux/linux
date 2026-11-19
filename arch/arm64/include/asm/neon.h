/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * linux/arch/arm64/include/asm/neon.h
 *
 * Copyright (C) 2013 Linaro Ltd <ard.biesheuvel@linaro.org>
 */

#ifndef __ASM_NEON_H
#define __ASM_NEON_H

#include <linux/args.h>
#include <linux/types.h>
#include <asm/fpsimd.h>

#define cpu_has_neon()		system_supports_fpsimd()

void kernel_neon_begin(struct user_fpsimd_state *);
void kernel_neon_end(struct user_fpsimd_state *);

/*
 * The certified FIPS crypto sources (arch/arm64/crypto/*-glue.c,
 * lib/crypto/arm64/sha*.h) call kernel_neon_begin()/kernel_neon_end() with no
 * argument, as 7.1's predecessors did.  They are inside the FIPS boundary and so
 * cannot be changed, and C has no overloading, so route by argument count: no
 * argument reaches the _legacy entry points, which pass the per-task buffer in
 * thread_struct, and one argument reaches the functions declared above.
 */
void kernel_neon_begin_legacy(void);
void kernel_neon_end_legacy(void);

/* two levels, so COUNT_ARGS() expands before the paste */
#define __kneon_cat(a, b)	a##b
#define __kneon_call(fn, n)	__kneon_cat(fn, n)
#define __kneon_begin0()	kernel_neon_begin_legacy()
#define __kneon_begin1(st)	kernel_neon_begin(st)
#define __kneon_end0()		kernel_neon_end_legacy()
#define __kneon_end1(st)	kernel_neon_end(st)

#define kernel_neon_begin(...) \
	__kneon_call(__kneon_begin, COUNT_ARGS(__VA_ARGS__))(__VA_ARGS__)
#define kernel_neon_end(...) \
	__kneon_call(__kneon_end, COUNT_ARGS(__VA_ARGS__))(__VA_ARGS__)

#endif /* ! __ASM_NEON_H */
