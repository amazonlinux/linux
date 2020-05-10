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
