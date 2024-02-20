/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2018-2022 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#include <linux/types.h>


#define IB_QPT_DRIVER 0xFF

#define ibdev_err(_ibdev, format, arg...) \
	dev_err(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#define ibdev_dbg(_ibdev, format, arg...) \
	dev_dbg(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#define ibdev_warn(_ibdev, format, arg...) \
	dev_warn(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#define ibdev_info(_ibdev, format, arg...) \
	dev_info(&((struct ib_device *)(_ibdev))->dev, format, ##arg)

#define ibdev_err_ratelimited(_ibdev, format, arg...) \
	dev_err_ratelimited(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#define ibdev_dbg_ratelimited(_ibdev, format, arg...) \
	dev_dbg_ratelimited(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#define ibdev_warn_ratelimited(_ibdev, format, arg...) \
	dev_warn_ratelimited(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#define ibdev_info_ratelimited(_ibdev, format, arg...) \
	dev_info_ratelimited(&((struct ib_device *)(_ibdev))->dev, format, ##arg)

#define IB_PORT_PHYS_STATE_LINK_UP 5

#include <linux/types.h>
#include <linux/device.h>

struct rdma_user_mmap_entry {
	struct ib_ucontext *ucontext;
	unsigned long start_pgoff;
	size_t npages;
};

/* Return the offset (in bytes) the user should pass to libc's mmap() */
static inline u64
rdma_user_mmap_get_offset(const struct rdma_user_mmap_entry *entry)
{
	return (u64)entry->start_pgoff << PAGE_SHIFT;
}

/*
 * Backported kernels don't keep refcnt on entries, hence they should not
 * be removed.
 */
static inline void
rdma_user_mmap_entry_remove(struct rdma_user_mmap_entry *entry)
{
}

static inline void rdma_user_mmap_entry_put(struct rdma_user_mmap_entry *entry)
{
}

#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#endif

enum {
	RDMA_NODE_UNSPECIFIED = 7,
};

typedef u8 port_t;

#endif /* _KCOMPAT_H_ */
