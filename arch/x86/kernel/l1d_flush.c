// SPDX-License-Identifier: GPL-2.0-only

#include <linux/mm.h>

#include <asm/cacheflush.h>

void *l1d_flush_alloc_pages(void)
{
	struct page *page;
	void *l1d_flush_pages = NULL;
	int i;

	/*
	 * This allocation for l1d_flush_pages is not tied to a VM/task's
	 * lifetime and so should not be charged to a memcg.
	 */
	page = alloc_pages(GFP_KERNEL, L1D_CACHE_ORDER);
	if (!page)
		return NULL;
	l1d_flush_pages = page_address(page);

	/*
	 * Initialize each page with a different pattern in
	 * order to protect against KSM in the nested
	 * virtualization case.
	 */
	for (i = 0; i < 1u << L1D_CACHE_ORDER; ++i) {
		memset(l1d_flush_pages + i * PAGE_SIZE, i + 1,
				PAGE_SIZE);
	}
	return l1d_flush_pages;
}
EXPORT_SYMBOL_GPL(l1d_flush_alloc_pages);

void l1d_flush_cleanup_pages(void *l1d_flush_pages)
{
	free_pages((unsigned long)l1d_flush_pages, L1D_CACHE_ORDER);
}
EXPORT_SYMBOL_GPL(l1d_flush_cleanup_pages);

void l1d_flush_populate_tlb(void *l1d_flush_pages)
{
	int size = PAGE_SIZE << L1D_CACHE_ORDER;

	asm volatile(
		/* First ensure the pages are in the TLB */
		"xorl	%%eax, %%eax\n"
		".Lpopulate_tlb:\n\t"
		"movzbl	(%[flush_pages], %%" _ASM_AX "), %%ecx\n\t"
		"addl	$4096, %%eax\n\t"
		"cmpl	%%eax, %[size]\n\t"
		"jne	.Lpopulate_tlb\n\t"
		"xorl	%%eax, %%eax\n\t"
		"cpuid\n\t"
		:: [flush_pages] "r" (l1d_flush_pages),
		    [size] "r" (size)
		: "eax", "ebx", "ecx", "edx");
}
EXPORT_SYMBOL_GPL(l1d_flush_populate_tlb);

int l1d_flush_hw(void)
{
	if (static_cpu_has(X86_FEATURE_FLUSH_L1D)) {
		wrmsrl(MSR_IA32_FLUSH_CMD, L1D_FLUSH);
		return 0;
	}
	return -ENOTSUPP;
}
EXPORT_SYMBOL_GPL(l1d_flush_hw);

void l1d_flush_sw(void *l1d_flush_pages)
{
	int size = PAGE_SIZE << L1D_CACHE_ORDER;

	asm volatile(
			/* Fill the cache */
			"xorl	%%eax, %%eax\n"
			".Lfill_cache:\n"
			"movzbl	(%[flush_pages], %%" _ASM_AX "), %%ecx\n\t"
			"addl	$64, %%eax\n\t"
			"cmpl	%%eax, %[size]\n\t"
			"jne	.Lfill_cache\n\t"
			"lfence\n"
			:: [flush_pages] "r" (l1d_flush_pages),
			[size] "r" (size)
			: "eax", "ecx");
}
EXPORT_SYMBOL_GPL(l1d_flush_sw);
