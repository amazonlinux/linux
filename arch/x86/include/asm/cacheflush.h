/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CACHEFLUSH_H
#define _ASM_X86_CACHEFLUSH_H

/* Caches aren't brain-dead on the intel. */
#include <asm-generic/cacheflush.h>
#include <asm/special_insns.h>

#define L1D_CACHE_ORDER 4
void clflush_cache_range(void *addr, unsigned int size);
void l1d_flush_populate_tlb(void *l1d_flush_pages);
void *l1d_flush_alloc_pages(void);
void l1d_flush_cleanup_pages(void *l1d_flush_pages);
void l1d_flush_sw(void *l1d_flush_pages);
int l1d_flush_hw(void);

#endif /* _ASM_X86_CACHEFLUSH_H */
