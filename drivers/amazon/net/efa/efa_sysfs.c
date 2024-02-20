// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright 2018-2023 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#include "efa_sysfs.h"
#include "kcompat.h"

#include <linux/device.h>
#include <linux/sysfs.h>

#include "efa_p2p.h"

static ssize_t p2p_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	return sysfs_emit(buf, "%s\n", efa_p2p_provider_string());
}

static DEVICE_ATTR_RO(p2p);

int efa_sysfs_init(struct efa_dev *dev)
{
	struct device *device = &dev->pdev->dev;

	if (device_create_file(device, &dev_attr_p2p))
		dev_err(device, "Failed to create P2P sysfs file\n");
	return 0;
}

void efa_sysfs_destroy(struct efa_dev *dev)
{
	device_remove_file(&dev->pdev->dev, &dev_attr_p2p);
}
