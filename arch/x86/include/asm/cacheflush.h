/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CACHEFLUSH_H
#define _ASM_X86_CACHEFLUSH_H

/* Caches aren't brain-dead on the intel. */
#include <asm-generic/cacheflush.h>
#include <asm/special_insns.h>

#define L1D_CACHE_ORDER 4

enum l1d_flush_options {
	L1D_FLUSH_POPULATE_TLB = 0x1,
};

void clflush_cache_range(void *addr, unsigned int size);
int l1d_flush_init_once(void);
void arch_l1d_flush(enum l1d_flush_options options);

#endif /* _ASM_X86_CACHEFLUSH_H */
