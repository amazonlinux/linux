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

typedef u32 port_t;

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

#include <rdma/ib_umem.h>

static inline dma_addr_t ib_umem_start_dma_addr(struct ib_umem *umem)
{
	return sg_dma_address(umem->sgt_append.sgt.sgl) + ib_umem_offset(umem);
}

#include <rdma/ib_umem.h>

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

enum efa_uverbs_attrs_create_cq_cmd_attr_ids {
	UVERBS_ATTR_CREATE_CQ_BUFFER_VA = 8,
	UVERBS_ATTR_CREATE_CQ_BUFFER_LENGTH,
	UVERBS_ATTR_CREATE_CQ_BUFFER_FD,
	UVERBS_ATTR_CREATE_CQ_BUFFER_OFFSET,
};

#endif /* _KCOMPAT_H_ */
