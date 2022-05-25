// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/dma-map-ops.h>
#include "direct.h"
#include <linux/moduleparam.h>

/*
 * A wrapper around dma_direct which does a readb on the memory being mapped
 * for DMA to ensure that it becomes resident.
 * Useful when running in a memory overcommit environment with lazy allocation
 * and free page reporting.
 */

/*
 * Set with kernel cmd line param:
 * page_touching.dma_page_touching_enable=y
 */
static bool dma_page_touching_enable __ro_after_init;
module_param_named(dma_page_touching_enable, dma_page_touching_enable, bool, 0400);
MODULE_PARM_DESC(dma_page_touching_enable,
		"Touch pages allocated for DMA to ensure they are resident");

static void touch_each_page(void *start_addr, size_t size)
{
	int addr_offset;

	for (addr_offset = 0; addr_offset < size; addr_offset += PAGE_SIZE)
		__raw_readb((char *)start_addr + addr_offset);
}

static void *page_touching_dma_alloc(struct device *dev, size_t size,
			dma_addr_t *dma_handle, gfp_t gfp,
			unsigned long attrs)
{
	char *kaddr = dma_direct_alloc(dev, size, dma_handle, gfp, attrs);

	if (!kaddr)
		return NULL;
	touch_each_page(kaddr, size);
	return kaddr;

}

static dma_addr_t page_touching_dma_map_page(struct device *dev, struct page *page,
		       unsigned long offset, size_t size,
		       enum dma_data_direction dir,
		       unsigned long attrs)
{
	dma_addr_t dma_handle = dma_direct_map_page(dev, page, offset, size, dir, attrs);

	if (!(dma_mapping_error(dev, dma_handle)))
		touch_each_page(page_to_virt(page) + offset, size);
	return dma_handle;
}

static int page_touching_dma_map_sg(struct device *dev, struct scatterlist *sglist,
	      int nents, enum dma_data_direction dir,
	      unsigned long attrs)
{
	struct scatterlist *sg;
	int i, ret = dma_direct_map_sg(dev, sglist, nents, dir, attrs);

	if (!ret)
		goto out;

	for_each_sg(sglist, sg, nents, i)
		touch_each_page(page_to_virt(sg_page(sg)) + sg->offset, sg->length);

out:
	return ret;

}

/*
 * Only a portion of the dma_map_ops interface is implemented here; enough for
 * the EC2 ENA / NVMe drivers to work.
 * Notibly missing is alloc_pages.
 */
const static struct dma_map_ops page_touching_dma_ops = {
	.alloc			= page_touching_dma_alloc,
	.free			= dma_direct_free,
	.mmap			= dma_common_mmap,
	.map_page		= page_touching_dma_map_page,
	.unmap_page		= dma_direct_unmap_page,
	.map_sg			= page_touching_dma_map_sg,
	.unmap_sg		= dma_direct_unmap_sg,
	.dma_supported		= dma_direct_supported,
	.sync_single_for_cpu	= dma_direct_sync_single_for_cpu,
	.sync_single_for_device	= dma_direct_sync_single_for_device,
	.sync_sg_for_cpu	= dma_direct_sync_sg_for_cpu,
	.dma_supported		= dma_direct_supported,
	.get_required_mask	= dma_direct_get_required_mask,
	.max_mapping_size	= dma_direct_max_mapping_size,
};

void setup_dma_page_touching_ops(struct device *dev)
{
	if (!dma_page_touching_enable || dev->dma_ops)
		return;

	dev_info(dev, "binding to page touching DMA ops\n");
	dev->dma_ops = &page_touching_dma_ops;
}
