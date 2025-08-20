/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2018-2025 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#include <linux/types.h>


#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#endif

#include <rdma/ib_umem.h>

#include <linux/count_zeros.h>

static inline unsigned long
efa_umem_find_best_pgsz(struct ib_umem *umem,
		        unsigned long pgsz_bitmap,
		        unsigned long virt)
{
	unsigned long curr_len = 0;
	dma_addr_t curr_base = ~0;
	unsigned long va, pgoff;
	struct scatterlist *sg;
	dma_addr_t mask;
	int i;

	umem->iova = va = virt;

	/* rdma_for_each_block() has a bug if the page size is smaller than the
	 * page size used to build the umem. For now prevent smaller page sizes
	 * from being returned.
	 */
	pgsz_bitmap &= GENMASK(BITS_PER_LONG - 1, PAGE_SHIFT);

	/* The best result is the smallest page size that results in the minimum
	 * number of required pages. Compute the largest page size that could
	 * work based on VA address bits that don't change.
	 */
	mask = pgsz_bitmap &
	       GENMASK(BITS_PER_LONG - 1,
		       bits_per((umem->length - 1 + virt) ^ virt));
	/* offset into first SGL */
	pgoff = umem->address & ~PAGE_MASK;

	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, i) {
		/* If the current entry is physically contiguous with the previous
		 * one, no need to take its start addresses into consideration.
		 */
		if (curr_base + curr_len != sg_dma_address(sg)) {

			curr_base = sg_dma_address(sg);
			curr_len = 0;

			/* Reduce max page size if VA/PA bits differ */
			mask |= (curr_base + pgoff) ^ va;

			/* The alignment of any VA matching a discontinuity point
			* in the physical memory sets the maximum possible page
			* size as this must be a starting point of a new page that
			* needs to be aligned.
			*/
			if (i != 0)
				mask |= va;
		}

		curr_len += sg_dma_len(sg);
		va += sg_dma_len(sg) - pgoff;

		pgoff = 0;
	}

	/* The mask accumulates 1's in each position where the VA and physical
	 * address differ, thus the length of trailing 0 is the largest page
	 * size that can pass the VA through to the physical.
	 */
	if (mask)
		pgsz_bitmap &= GENMASK(count_trailing_zeros(mask), 0);
	return pgsz_bitmap ? rounddown_pow_of_two(pgsz_bitmap) : 0;
}

static inline bool __efa_rdma_block_iter_next(struct ib_block_iter *biter)
{
	unsigned int block_offset;
	unsigned int delta;

	if (!biter->__sg_nents || !biter->__sg)
		return false;

	biter->__dma_addr = sg_dma_address(biter->__sg) + biter->__sg_advance;
	block_offset = biter->__dma_addr & (BIT_ULL(biter->__pg_bit) - 1);
	delta = BIT_ULL(biter->__pg_bit) - block_offset;

	while (biter->__sg_nents && biter->__sg &&
	       sg_dma_len(biter->__sg) - biter->__sg_advance <= delta) {
		delta -= sg_dma_len(biter->__sg) - biter->__sg_advance;
		biter->__sg_advance = 0;
		biter->__sg = sg_next(biter->__sg);
		biter->__sg_nents--;
	}
	biter->__sg_advance += delta;

	return true;
}

static inline bool __efa_rdma_umem_block_iter_next(struct ib_block_iter *biter)
{
	return __efa_rdma_block_iter_next(biter);
}

/**
 * rdma_umem_for_each_dma_block - iterate over contiguous DMA blocks of the umem
 * @umem: umem to iterate over
 * @pgsz: Page size to split the list into
 *
 * pgsz must be <= PAGE_SIZE or computed by ib_umem_find_best_pgsz(). The
 * returned DMA blocks will be aligned to pgsz and span the range:
 * ALIGN_DOWN(umem->address, pgsz) to ALIGN(umem->address + umem->length, pgsz)
 *
 * Performs exactly ib_umem_num_dma_blocks() iterations.
 */
#define efa_rdma_umem_for_each_dma_block(umem, biter, pgsz)                    \
	for (__rdma_umem_block_iter_start(biter, umem, pgsz);                  \
	     __efa_rdma_umem_block_iter_next(biter);)

typedef u8 port_t;

/*
 * Add the pseudo keyword 'fallthrough' so case statement blocks
 * must end with any of these keywords:
 *   break;
 *   fallthrough;
 *   continue;
 *   goto <label>;
 *   return [expression];
 *
 *  gcc: https://gcc.gnu.org/onlinedocs/gcc/Statement-Attributes.html#Statement-Attributes
 */
#if __has_attribute(__fallthrough__)
# define fallthrough                    __attribute__((__fallthrough__))
#else
# define fallthrough                    do {} while (0)  /* fallthrough */
#endif

static inline dma_addr_t ib_umem_start_dma_addr(struct ib_umem *umem)
{
	return U64_MAX;
}

static inline bool ib_umem_is_contiguous(struct ib_umem *umem)
{
	dma_addr_t dma_addr;
	unsigned long pgsz;

	/*
	 * Select the smallest aligned page that can contain the whole umem if
	 * it was contiguous.
	 */
	dma_addr = ib_umem_start_dma_addr(umem);
	pgsz = roundup_pow_of_two((dma_addr ^ (umem->length - 1 + dma_addr)) + 1);
	return !!ib_umem_find_best_pgsz(umem, pgsz, dma_addr);
}

#include <rdma/uverbs_ioctl.h>

static inline struct uverbs_attr_bundle *
rdma_udata_to_uverbs_attr_bundle(struct ib_udata *udata)
{
	return container_of(udata, struct uverbs_attr_bundle, driver_udata);
}

enum efa_uverbs_attrs_create_cq_cmd_attr_ids {
	UVERBS_ATTR_CREATE_CQ_BUFFER_VA = 8,
	UVERBS_ATTR_CREATE_CQ_BUFFER_LENGTH,
	UVERBS_ATTR_CREATE_CQ_BUFFER_FD,
	UVERBS_ATTR_CREATE_CQ_BUFFER_OFFSET,
};

#endif /* _KCOMPAT_H_ */
