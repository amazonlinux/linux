// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2024, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lnet/lnds/efalnd/kcompat.h
 *
 * Author: Michael Margolin <mrgolin@amazon.com>
 */

#include <rdma/ib_verbs.h>

#ifndef HAVE_IBDEV_TO_NODE
/**
 * ibdev_to_node - return the NUMA node for a given ib_device
 * @dev:	device to get the NUMA node for.
 */
static inline int ibdev_to_node(struct ib_device *ibdev)
{
	struct device *parent = ibdev->dev.parent;

	if (!parent)
		return NUMA_NO_NODE;
	return dev_to_node(parent);
}
#endif

#ifndef HAVE_SYSFS_EMIT_AT
/**
 *	sysfs_emit_at - scnprintf equivalent, aware of PAGE_SIZE buffer.
 *	@buf:	start of PAGE_SIZE buffer.
 *	@at:	offset in @buf to start write in bytes
 *		@at must be >= 0 && < PAGE_SIZE
 *	@fmt:	format
 *	@...:	optional arguments to @fmt
 *
 *
 * Returns number of characters written starting at &@buf[@at].
 */
static inline int sysfs_emit_at(char *buf, int at, const char *fmt, ...)
{
	va_list args;
	int len;

	if (WARN(!buf || offset_in_page(buf) || at < 0 || at >= PAGE_SIZE,
		 "invalid sysfs_emit_at: buf:%p at:%d\n", buf, at))
		return 0;

	va_start(args, fmt);
	len = vscnprintf(buf + at, PAGE_SIZE - at, fmt, args);
	va_end(args);

	return len;
}
#endif