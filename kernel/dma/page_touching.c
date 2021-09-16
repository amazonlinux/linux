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
#include <linux/moduleparam.h>
#include <linux/dmi.h>

/*
 * DMA page touching support for memory overcommit environments.
 * 
 * In environments with memory overcommit and lazy allocation, pages may not
 * be physically resident even though they're in the guest's address space.
 * This causes DMA operations to fail. By touching pages before DMA, we ensure
 * they become resident.
 *
 * This is integrated directly into dma_direct_map_phys() via a device flag,
 * avoiding the need for custom dma_ops.
 */

/*
 * Set with kernel cmd line param:
 * page_touching.dma_page_touching_enable=y
 */
static bool dma_page_touching_enable __ro_after_init;
module_param_named(dma_page_touching_enable, dma_page_touching_enable, bool, 0400);
MODULE_PARM_DESC(dma_page_touching_enable,
		"Touch pages allocated for DMA to ensure they are resident");

void dma_enable_page_touching(struct device *dev)
{
	if (!dma_page_touching_enable)
		return;

	dev_info(dev, "enabling DMA page touching\n");
	dev->dma_touch_pages = true;
}

static const struct dmi_system_id pt_enable_table[] __initconst = {
	{
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Amazon EC2"),
			DMI_MATCH(DMI_PRODUCT_NAME, "caspian"),
		},
	},
	{},
};

static int __init dmi_enable_pt(void)
{
	if (dmi_check_system(pt_enable_table)) {
		pr_info("Automatically enabling page touching for Caspian\n");
		dma_page_touching_enable = 1;
	}
	return 0;
}
arch_initcall(dmi_enable_pt)
