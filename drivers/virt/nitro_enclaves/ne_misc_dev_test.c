// SPDX-License-Identifier: GPL-2.0

#include <kunit/test.h>
#include "ne_pci_dev.h"

#define MAX_PHYS_REGIONS	16
#define INVALID_VALUE		(~0ull)

struct ne_phys_regions_test {
	u64           paddr;
	u64           size;
	int           expect_rc;
	unsigned long expect_num;
	u64           expect_last_paddr;
	u64           expect_last_size;
} phys_regions_test_cases[] = {
	/*
	 * Add the region from 0x1000 to (0x1000 + 0x200000 - 1):
	 *   Expected result:
	 *       Failed, start address is not 2M-aligned
	 *
	 * Now the instance of struct ne_phys_contig_mem_regions is:
	 *   num = 0
	 *   regions = {}
	 */
	{0x1000, 0x200000, -EINVAL, 0, INVALID_VALUE, INVALID_VALUE},

	/*
	 * Add the region from 0x200000 to (0x200000 + 0x1000 - 1):
	 *   Expected result:
	 *       Failed, size is not 2M-aligned
	 *
	 * Now the instance of struct ne_phys_contig_mem_regions is:
	 *   num = 0
	 *   regions = {}
	 */
	{0x200000, 0x1000, -EINVAL, 0, INVALID_VALUE, INVALID_VALUE},

	/*
	 * Add the region from 0x200000 to (0x200000 + 0x200000 - 1):
	 *   Expected result:
	 *       Successful
	 *
	 * Now the instance of struct ne_phys_contig_mem_regions is:
	 *   num = 1
	 *   regions = {
	 *       {start=0x200000, end=0x3fffff}, // len=0x200000
	 *   }
	 */
	{0x200000, 0x200000, 0, 1, 0x200000, 0x200000},

	/*
	 * Add the region from 0x0 to (0x0 + 0x200000 - 1):
	 *   Expected result:
	 *       Successful
	 *
	 * Now the instance of struct ne_phys_contig_mem_regions is:
	 *   num = 2
	 *   regions = {
	 *       {start=0x200000, end=0x3fffff}, // len=0x200000
	 *       {start=0x0,      end=0x1fffff}, // len=0x200000
	 *   }
	 */
	{0x0, 0x200000, 0, 2, 0x0, 0x200000},

	/*
	 * Add the region from 0x600000 to (0x600000 + 0x400000 - 1):
	 *   Expected result:
	 *       Successful
	 *
	 * Now the instance of struct ne_phys_contig_mem_regions is:
	 *   num = 3
	 *   regions = {
	 *       {start=0x200000, end=0x3fffff}, // len=0x200000
	 *       {start=0x0,      end=0x1fffff}, // len=0x200000
	 *       {start=0x600000, end=0x9fffff}, // len=0x400000
	 *   }
	 */
	{0x600000, 0x400000, 0, 3, 0x600000, 0x400000},

	/*
	 * Add the region from 0xa00000 to (0xa00000 + 0x400000 - 1):
	 *   Expected result:
	 *       Successful, merging case!
	 *
	 * Now the instance of struct ne_phys_contig_mem_regions is:
	 *   num = 3
	 *   regions = {
	 *       {start=0x200000, end=0x3fffff}, // len=0x200000
	 *       {start=0x0,      end=0x1fffff}, // len=0x200000
	 *       {start=0x600000, end=0xdfffff}, // len=0x800000
	 *   }
	 */
	{0xa00000, 0x400000, 0, 3, 0x600000, 0x800000},

	/*
	 * Add the region from 0x1000 to (0x1000 + 0x200000 - 1):
	 *   Expected result:
	 *       Failed, start address is not 2M-aligned
	 *
	 * Now the instance of struct ne_phys_contig_mem_regions is:
	 *   num = 3
	 *   regions = {
	 *       {start=0x200000, end=0x3fffff}, // len=0x200000
	 *       {start=0x0,      end=0x1fffff}, // len=0x200000
	 *       {start=0x600000, end=0xdfffff}, // len=0x800000
	 *   }
	 */
	{0x1000, 0x200000, -EINVAL, 3, 0x600000, 0x800000},
};

static void ne_misc_dev_test_merge_phys_contig_memory_regions(struct kunit *test)
{
	struct ne_phys_contig_mem_regions phys_contig_mem_regions = {};
	int rc = 0;
	int i = 0;

	phys_contig_mem_regions.regions = kunit_kcalloc(test, MAX_PHYS_REGIONS,
							sizeof(*phys_contig_mem_regions.regions),
							GFP_KERNEL);
	KUNIT_ASSERT_TRUE(test, phys_contig_mem_regions.regions);

	for (i = 0; i < ARRAY_SIZE(phys_regions_test_cases); i++) {
		struct ne_phys_regions_test *test_case = &phys_regions_test_cases[i];
		unsigned long num = 0;

		rc = ne_merge_phys_contig_memory_regions(&phys_contig_mem_regions,
							 test_case->paddr, test_case->size);
		KUNIT_EXPECT_EQ(test, rc, test_case->expect_rc);
		KUNIT_EXPECT_EQ(test, phys_contig_mem_regions.num, test_case->expect_num);

		if (test_case->expect_last_paddr == INVALID_VALUE)
			continue;

		num = phys_contig_mem_regions.num;
		KUNIT_EXPECT_EQ(test, phys_contig_mem_regions.regions[num - 1].start,
				test_case->expect_last_paddr);
		KUNIT_EXPECT_EQ(test, range_len(&phys_contig_mem_regions.regions[num - 1]),
				test_case->expect_last_size);
	}

	kunit_kfree(test, phys_contig_mem_regions.regions);
}

static struct kunit_case ne_misc_dev_test_cases[] = {
	KUNIT_CASE(ne_misc_dev_test_merge_phys_contig_memory_regions),
	{}
};

static struct kunit_suite ne_misc_dev_test_suite = {
	.name = "ne_misc_dev_test",
	.test_cases = ne_misc_dev_test_cases,
};

kunit_test_suite(ne_misc_dev_test_suite);

/* ── Tests for ne_build_backing_ranges ─────────────────────────── */

/* Single contiguous page → 1 range */
static void ne_test_build_ranges_single_page(struct kunit *test)
{
	struct page *page = alloc_page(GFP_KERNEL);
	struct slot_backing_range ranges[SLOT_MAX_BACKING_RANGES] = {};
	u32 num_ranges = 0;
	int rc;

	KUNIT_ASSERT_NOT_NULL(test, page);

	rc = ne_build_backing_ranges(&page, 1, ranges,
				     SLOT_MAX_BACKING_RANGES, &num_ranges, 0);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, num_ranges, 1);
	KUNIT_EXPECT_EQ(test, ranges[0].phys_addr, (u64)page_to_phys(page));
	KUNIT_EXPECT_EQ(test, ranges[0].size, (u64)PAGE_SIZE);

	__free_page(page);
}

/* Contiguous pages from alloc_pages(order=2) → 1 range */
static void ne_test_build_ranges_contiguous(struct kunit *test)
{
	unsigned int order = 2; /* 4 pages */
	unsigned int nr = 1 << order;
	struct page *block = alloc_pages(GFP_KERNEL, order);
	struct page **pages;
	struct slot_backing_range ranges[SLOT_MAX_BACKING_RANGES] = {};
	u32 num_ranges = 0;
	unsigned int i;
	int rc;

	KUNIT_ASSERT_NOT_NULL(test, block);

	pages = kunit_kcalloc(test, nr, sizeof(*pages), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, pages);
	for (i = 0; i < nr; i++)
		pages[i] = block + i;

	rc = ne_build_backing_ranges(pages, nr, ranges,
				     SLOT_MAX_BACKING_RANGES, &num_ranges, 0);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, num_ranges, 1);
	KUNIT_EXPECT_EQ(test, ranges[0].phys_addr, (u64)page_to_phys(block));
	KUNIT_EXPECT_EQ(test, ranges[0].size, (u64)(nr * PAGE_SIZE));

	kunit_kfree(test, pages);
	__free_pages(block, order);
}

/* Two separate allocations → 2 ranges (likely non-contiguous) */
static void ne_test_build_ranges_two_blocks(struct kunit *test)
{
	struct page *block_a = alloc_pages(GFP_KERNEL, 1); /* 2 pages */
	struct page *block_b = alloc_pages(GFP_KERNEL, 1); /* 2 pages */
	struct page *pages[4];
	struct slot_backing_range ranges[SLOT_MAX_BACKING_RANGES] = {};
	u32 num_ranges = 0;
	int rc;

	KUNIT_ASSERT_NOT_NULL(test, block_a);
	KUNIT_ASSERT_NOT_NULL(test, block_b);

	if (page_to_phys(block_b) == page_to_phys(block_a) + 2 * PAGE_SIZE) {
		__free_pages(block_a, 1);
		__free_pages(block_b, 1);
		kunit_skip(test, "blocks are adjacent, cannot test two ranges");
	}

	/* Arrange: block_a pages, then block_b pages */
	pages[0] = block_a;
	pages[1] = block_a + 1;
	pages[2] = block_b;
	pages[3] = block_b + 1;

	rc = ne_build_backing_ranges(pages, 4, ranges,
				     SLOT_MAX_BACKING_RANGES, &num_ranges, 0);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, num_ranges, 2);
	KUNIT_EXPECT_EQ(test, ranges[0].phys_addr,
			(u64)page_to_phys(block_a));
	KUNIT_EXPECT_EQ(test, ranges[0].size, (u64)(2 * PAGE_SIZE));
	KUNIT_EXPECT_EQ(test, ranges[1].phys_addr,
			(u64)page_to_phys(block_b));
	KUNIT_EXPECT_EQ(test, ranges[1].size, (u64)(2 * PAGE_SIZE));

	__free_pages(block_a, 1);
	__free_pages(block_b, 1);
}

/* Exceed max_ranges → -EINVAL */
static void ne_test_build_ranges_exceeds_max(struct kunit *test)
{
	struct page *a = alloc_page(GFP_KERNEL);
	struct page *b = alloc_page(GFP_KERNEL);
	struct page *pages[2];
	struct slot_backing_range ranges[1] = {};
	u32 num_ranges = 0;
	int rc;

	KUNIT_ASSERT_NOT_NULL(test, a);
	KUNIT_ASSERT_NOT_NULL(test, b);

	if (page_to_phys(a) + PAGE_SIZE == page_to_phys(b) ||
	    page_to_phys(b) + PAGE_SIZE == page_to_phys(a)) {
		__free_page(a);
		__free_page(b);
		kunit_skip(test, "pages are contiguous, cannot test overflow");
	}

	pages[0] = a;
	pages[1] = b;

	rc = ne_build_backing_ranges(pages, 2, ranges, 1, &num_ranges, 0);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	__free_page(a);
	__free_page(b);
}

/* Zero pages → no change to num_ranges */
static void ne_test_build_ranges_empty(struct kunit *test)
{
	struct slot_backing_range ranges[SLOT_MAX_BACKING_RANGES] = {};
	u32 num_ranges = 0;
	int rc;

	rc = ne_build_backing_ranges(NULL, 0, ranges,
				     SLOT_MAX_BACKING_RANGES, &num_ranges, 0);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, num_ranges, 0);
}

/* Multi-region append: two calls with different shm_ids preserve both */
static void ne_test_build_ranges_multi_region(struct kunit *test)
{
	struct page *page_a = alloc_page(GFP_KERNEL);
	struct page *page_b = alloc_page(GFP_KERNEL);
	struct slot_backing_range ranges[SLOT_MAX_BACKING_RANGES] = {};
	u32 num_ranges = 0;
	int rc;

	KUNIT_ASSERT_NOT_NULL(test, page_a);
	KUNIT_ASSERT_NOT_NULL(test, page_b);

	/* First region: shm_id=1 */
	rc = ne_build_backing_ranges(&page_a, 1, ranges,
				     SLOT_MAX_BACKING_RANGES, &num_ranges, 1);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, num_ranges, 1);

	/* Second region: shm_id=2, appends */
	rc = ne_build_backing_ranges(&page_b, 1, ranges,
				     SLOT_MAX_BACKING_RANGES, &num_ranges, 2);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, num_ranges, 2);

	/* Verify both entries preserved with correct shm_ids */
	KUNIT_EXPECT_EQ(test, ranges[0].phys_addr, (u64)page_to_phys(page_a));
	KUNIT_EXPECT_EQ(test, ranges[0].size,
			(u64)(PAGE_SIZE | (1ULL << NE_RANGE_SHMID_SHIFT)));
	KUNIT_EXPECT_EQ(test, ranges[1].phys_addr, (u64)page_to_phys(page_b));
	KUNIT_EXPECT_EQ(test, ranges[1].size,
			(u64)(PAGE_SIZE | (2ULL << NE_RANGE_SHMID_SHIFT)));

	__free_page(page_a);
	__free_page(page_b);
}

/* Adjacent pages with different shm_ids must NOT be coalesced. */
static void ne_test_build_ranges_shmid_prevents_coalesce(struct kunit *test)
{
	struct page *block = alloc_pages(GFP_KERNEL, 1); /* 2 adjacent pages */
	struct slot_backing_range ranges[SLOT_MAX_BACKING_RANGES] = {};
	u32 num_ranges = 0;
	struct page *p0, *p1;
	int rc;

	KUNIT_ASSERT_NOT_NULL(test, block);
	p0 = block;
	p1 = block + 1;

	rc = ne_build_backing_ranges(&p0, 1, ranges,
				     SLOT_MAX_BACKING_RANGES, &num_ranges, 1);
	KUNIT_EXPECT_EQ(test, rc, 0);

	rc = ne_build_backing_ranges(&p1, 1, ranges,
				     SLOT_MAX_BACKING_RANGES, &num_ranges, 2);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, num_ranges, 2);

	__free_pages(block, 1);
}

static struct kunit_case ne_build_ranges_test_cases[] = {
	KUNIT_CASE(ne_test_build_ranges_single_page),
	KUNIT_CASE(ne_test_build_ranges_contiguous),
	KUNIT_CASE(ne_test_build_ranges_two_blocks),
	KUNIT_CASE(ne_test_build_ranges_exceeds_max),
	KUNIT_CASE(ne_test_build_ranges_empty),
	KUNIT_CASE(ne_test_build_ranges_multi_region),
	KUNIT_CASE(ne_test_build_ranges_shmid_prevents_coalesce),
	{}
};

static struct kunit_suite ne_build_ranges_test_suite = {
	.name = "ne_build_backing_ranges_test",
	.test_cases = ne_build_ranges_test_cases,
};

kunit_test_suite(ne_build_ranges_test_suite);

/* ── Tests for early_ne_mempool parser ─────────────────────────── */

/*
 * Helper: reset the global parser state, feed a cmdline string,
 * and return the number of parsed entries.  The test can then
 * inspect ne_mempool_layout[] directly.
 */
static int __init ne_test_parse(const char *input)
{
	char buf[128];

	ne_mempool_nr_entries = 0;
	memset(ne_mempool_layout, 0, sizeof(ne_mempool_layout));
	strscpy(buf, input, sizeof(buf));
	early_ne_mempool(buf);
	return ne_mempool_nr_entries;
}

/* Plain percentage: "80%" */
static void __init ne_test_parse_plain_pct(struct kunit *test)
{
	int n = ne_test_parse("80%");

	KUNIT_EXPECT_EQ(test, n, 1);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].pct, 80);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].size_mb, 0UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].subtract_mb, 0UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].nid, NUMA_NO_NODE);
}

/* Percentage with node: "95%@0" */
static void __init ne_test_parse_pct_at_node(struct kunit *test)
{
	int n = ne_test_parse("95%@0");

	KUNIT_EXPECT_EQ(test, n, 1);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].pct, 95);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].subtract_mb, 0UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].nid, 0);
}

/* Percentage with subtract: "95%-1G" */
static void __init ne_test_parse_pct_minus_size(struct kunit *test)
{
	int n = ne_test_parse("95%-1G");

	KUNIT_EXPECT_EQ(test, n, 1);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].pct, 95);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].subtract_mb, 1024UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].nid, NUMA_NO_NODE);
}

/* Percentage with subtract and node: "95%-1G@0" */
static void __init ne_test_parse_pct_minus_size_at_node(struct kunit *test)
{
	int n = ne_test_parse("95%-1G@0");

	KUNIT_EXPECT_EQ(test, n, 1);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].pct, 95);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].subtract_mb, 1024UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].nid, 0);
}

/* Percentage with subtract in MiB: "95%-512M" */
static void __init ne_test_parse_pct_minus_mib(struct kunit *test)
{
	int n = ne_test_parse("95%-512M");

	KUNIT_EXPECT_EQ(test, n, 1);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].pct, 95);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].subtract_mb, 512UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].nid, NUMA_NO_NODE);
}

/* Percentage with add: "50%+2G" */
static void __init ne_test_parse_pct_plus_size(struct kunit *test)
{
	int n = ne_test_parse("50%+2G");

	KUNIT_EXPECT_EQ(test, n, 1);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].pct, 50);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].add_mb, 2048UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].subtract_mb, 0UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].nid, NUMA_NO_NODE);
}

/* Percentage with add and node: "50%+2G@0" */
static void __init ne_test_parse_pct_plus_size_at_node(struct kunit *test)
{
	int n = ne_test_parse("50%+2G@0");

	KUNIT_EXPECT_EQ(test, n, 1);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].pct, 50);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].add_mb, 2048UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].subtract_mb, 0UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].nid, 0);
}

/* Percentage with add in MiB: "50%+512M" */
static void __init ne_test_parse_pct_plus_mib(struct kunit *test)
{
	int n = ne_test_parse("50%+512M");

	KUNIT_EXPECT_EQ(test, n, 1);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].pct, 50);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].add_mb, 512UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].subtract_mb, 0UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].nid, NUMA_NO_NODE);
}

/* Mixed entries with + and -: "50%+2G@0,95%-1G@1" */
static void __init ne_test_parse_mixed_add_sub(struct kunit *test)
{
	int n = ne_test_parse("50%+2G@0,95%-1G@1");

	KUNIT_EXPECT_EQ(test, n, 2);

	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].pct, 50);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].add_mb, 2048UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].subtract_mb, 0UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].nid, 0);

	KUNIT_EXPECT_EQ(test, ne_mempool_layout[1].pct, 95);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[1].subtract_mb, 1024UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[1].add_mb, 0UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[1].nid, 1);
}

/* Absolute size: "4G" */
static void __init ne_test_parse_absolute(struct kunit *test)
{
	int n = ne_test_parse("4G");

	KUNIT_EXPECT_EQ(test, n, 1);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].pct, 0);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].size_mb, 4096UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].subtract_mb, 0UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].nid, NUMA_NO_NODE);
}

/* Absolute size with node: "4G@1" */
static void __init ne_test_parse_absolute_at_node(struct kunit *test)
{
	int n = ne_test_parse("4G@1");

	KUNIT_EXPECT_EQ(test, n, 1);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].size_mb, 4096UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].nid, 1);
}

/* Mixed entries: "95%-1G@0,4G@1" */
static void __init ne_test_parse_mixed(struct kunit *test)
{
	int n = ne_test_parse("95%-1G@0,4G@1");

	KUNIT_EXPECT_EQ(test, n, 2);

	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].pct, 95);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].subtract_mb, 1024UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].nid, 0);

	KUNIT_EXPECT_EQ(test, ne_mempool_layout[1].pct, 0);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[1].size_mb, 4096UL);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[1].nid, 1);
}

/* Empty string: no entries */
static void __init ne_test_parse_empty(struct kunit *test)
{
	int n = ne_test_parse("");

	KUNIT_EXPECT_EQ(test, n, 0);
}

/* 100% with large subtract: should not underflow */
static void __init ne_test_parse_100pct_minus_large(struct kunit *test)
{
	int n = ne_test_parse("100%-200G");

	KUNIT_EXPECT_EQ(test, n, 1);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].pct, 100);
	KUNIT_EXPECT_EQ(test, ne_mempool_layout[0].subtract_mb, 200UL * 1024);
	/* The actual clamping to 0 happens in ne_resolve_pct, not the parser */
}

static struct kunit_case ne_mempool_parse_test_cases[] = {
	KUNIT_CASE(ne_test_parse_plain_pct),
	KUNIT_CASE(ne_test_parse_pct_at_node),
	KUNIT_CASE(ne_test_parse_pct_minus_size),
	KUNIT_CASE(ne_test_parse_pct_minus_size_at_node),
	KUNIT_CASE(ne_test_parse_pct_minus_mib),
	KUNIT_CASE(ne_test_parse_pct_plus_size),
	KUNIT_CASE(ne_test_parse_pct_plus_size_at_node),
	KUNIT_CASE(ne_test_parse_pct_plus_mib),
	KUNIT_CASE(ne_test_parse_mixed_add_sub),
	KUNIT_CASE(ne_test_parse_absolute),
	KUNIT_CASE(ne_test_parse_absolute_at_node),
	KUNIT_CASE(ne_test_parse_mixed),
	KUNIT_CASE(ne_test_parse_empty),
	KUNIT_CASE(ne_test_parse_100pct_minus_large),
	{}
};

static struct kunit_suite ne_mempool_parse_test_suite = {
	.name = "ne_mempool_parse_test",
	.test_cases = ne_mempool_parse_test_cases,
};

kunit_test_suite(ne_mempool_parse_test_suite);
