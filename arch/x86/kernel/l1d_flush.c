/*
 * This software-based L1D flush implementation is taken from the following
 * functions from KVM:
 *
 * o arch/x86/kvm/vmx/vmx.c::vmx_setup_l1d_flush()
 * o arch/x86/kvm/vmx/vmx.c::vmx_l1d_flush()
 *
 * As we did in the AL2 5.4 version this version doesn't populate the
 * TLB and only performs the cache filling part.
 */
#include <linux/mm.h>
#include <asm/l1d_flush.h>

#define L1D_CACHE_ORDER 4

static void *l1d_flush_pages;

void __init l1d_flush_init(void)
{
	struct page *page;
	int i;

	/*
	 * This allocation for l1d_flush_pages is not tied to a task's
	 * lifetime and so should not be charged to a memcg.
	 */
	page = alloc_pages(GFP_KERNEL, L1D_CACHE_ORDER);
	BUG_ON(!page);

	l1d_flush_pages = page_address(page);

	/*
	 * The original implementation in vmx_l1d_flush() does this
	 * initialization to protect against KSM for nested Virt.
	 * Let's keep it just in case.
	 */
	for (i = 0; i < 1u << L1D_CACHE_ORDER; ++i) {
		memset(l1d_flush_pages + i * PAGE_SIZE, i + 1,
				PAGE_SIZE);
	}
}

void l1d_flush_sw(void)
{
	int size = PAGE_SIZE << L1D_CACHE_ORDER;

	BUG_ON(!l1d_flush_pages);

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
