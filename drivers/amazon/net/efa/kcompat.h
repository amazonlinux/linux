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

#include <linux/dma-buf.h>
#include <linux/dma-resv.h>
#include <rdma/ib_umem.h>

MODULE_IMPORT_NS(DMA_BUF);

static inline void
ib_umem_dmabuf_unsupported_move_notify(struct dma_buf_attachment *attach)
{
	struct ib_umem_dmabuf *umem_dmabuf = attach->importer_priv;

	ibdev_warn_ratelimited(umem_dmabuf->umem.ibdev,
			       "Invalidate callback should not be called when memory is pinned\n");
}

static struct dma_buf_attach_ops ib_umem_dmabuf_attach_pinned_ops = {
	.allow_peer2peer = true,
	.move_notify = ib_umem_dmabuf_unsupported_move_notify,
};

static inline
struct ib_umem_dmabuf *ib_umem_dmabuf_get_pinned(struct ib_device *device,
						 unsigned long offset,
						 size_t size, int fd,
						 int access)
{
	struct ib_umem_dmabuf *umem_dmabuf;
	int err;

	umem_dmabuf = ib_umem_dmabuf_get(device, offset, size, fd, access,
					 &ib_umem_dmabuf_attach_pinned_ops);
	if (IS_ERR(umem_dmabuf))
		return umem_dmabuf;

	dma_resv_lock(umem_dmabuf->attach->dmabuf->resv, NULL);
	err = dma_buf_pin(umem_dmabuf->attach);
	if (err)
		goto err_release;

	err = ib_umem_dmabuf_map_pages(umem_dmabuf);
	if (err)
		goto err_unpin;
	dma_resv_unlock(umem_dmabuf->attach->dmabuf->resv);

	return umem_dmabuf;

err_unpin:
	dma_buf_unpin(umem_dmabuf->attach);
err_release:
	dma_resv_unlock(umem_dmabuf->attach->dmabuf->resv);
	ib_umem_release(&umem_dmabuf->umem);
	return ERR_PTR(err);
}

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
