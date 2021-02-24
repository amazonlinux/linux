// SPDX-License-Identifier: GPL-2.0
/*
 * Virtual Machine Generation ID driver
 *
 * Copyright (C) 2018 Red Hat Inc. All rights reserved.
 *
 * Copyright (C) 2020 Amazon. All rights reserved.
 *
 *	Authors:
 *	  Adrian Catangiu <acatan@amazon.com>
 *	  Or Idgar <oridgar@gmail.com>
 *	  Gal Hammer <ghammer@redhat.com>
 *
 */
#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/uuid.h>
#include <linux/sysgenid.h>

#define DEV_NAME "vmgenid"
ACPI_MODULE_NAME(DEV_NAME);

struct vmgenid_data {
	uuid_t uuid;
	void *uuid_iomap;
};
static struct vmgenid_data vmgenid_data;

static int vmgenid_acpi_map(struct vmgenid_data *priv, acpi_handle handle)
{
	int i;
	phys_addr_t phys_addr;
	struct acpi_buffer buffer = { ACPI_ALLOCATE_BUFFER, NULL };
	acpi_status status;
	union acpi_object *pss;
	union acpi_object *element;

	status = acpi_evaluate_object(handle, "ADDR", NULL, &buffer);
	if (ACPI_FAILURE(status)) {
		ACPI_EXCEPTION((AE_INFO, status, "Evaluating ADDR"));
		return -ENODEV;
	}
	pss = buffer.pointer;
	if (!pss || pss->type != ACPI_TYPE_PACKAGE || pss->package.count != 2)
		return -EINVAL;

	phys_addr = 0;
	for (i = 0; i < pss->package.count; i++) {
		element = &(pss->package.elements[i]);
		if (element->type != ACPI_TYPE_INTEGER)
			return -EINVAL;
		phys_addr |= element->integer.value << i * 32;
	}

	priv->uuid_iomap = acpi_os_map_memory(phys_addr, sizeof(uuid_t));
	if (!priv->uuid_iomap) {
		pr_err("Could not map memory at 0x%llx, size %u\n",
			   phys_addr,
			   (u32) sizeof(uuid_t));
		return -ENOMEM;
	}

	memcpy_fromio(&priv->uuid, priv->uuid_iomap, sizeof(uuid_t));

	return 0;
}

static int vmgenid_acpi_add(struct acpi_device *device)
{
	int ret;

	if (!device)
		return -EINVAL;
	device->driver_data = &vmgenid_data;

	ret = vmgenid_acpi_map(device->driver_data, device->handle);
	if (ret < 0) {
		pr_err("vmgenid: failed to map acpi device\n");
		device->driver_data = NULL;
	}

	return ret;
}

static int vmgenid_acpi_remove(struct acpi_device *device)
{
	if (!device || acpi_driver_data(device) != &vmgenid_data)
		return -EINVAL;
	device->driver_data = NULL;

	if (vmgenid_data.uuid_iomap)
		acpi_os_unmap_memory(vmgenid_data.uuid_iomap, sizeof(uuid_t));
	vmgenid_data.uuid_iomap = NULL;

	return 0;
}

static void vmgenid_acpi_notify(struct acpi_device *device, u32 event)
{
	uuid_t old_uuid;

	if (!device || acpi_driver_data(device) != &vmgenid_data) {
		pr_err("VMGENID notify with unexpected driver private data\n");
		return;
	}

	/* update VM Generation UUID */
	old_uuid = vmgenid_data.uuid;
	memcpy_fromio(&vmgenid_data.uuid, vmgenid_data.uuid_iomap, sizeof(uuid_t));

	if (memcmp(&old_uuid, &vmgenid_data.uuid, sizeof(uuid_t))) {
		/* HW uuid updated */
		sysgenid_bump_generation();
		add_device_randomness(&vmgenid_data.uuid, sizeof(uuid_t));
	}
}

static const struct acpi_device_id vmgenid_ids[] = {
	{"VMGENID", 0},
	{"QEMUVGID", 0},
	{"", 0},
};

static struct acpi_driver acpi_vmgenid_driver = {
	.name = "vm_generation_id",
	.ids = vmgenid_ids,
	.owner = THIS_MODULE,
	.ops = {
		.add = vmgenid_acpi_add,
		.remove = vmgenid_acpi_remove,
		.notify = vmgenid_acpi_notify,
	}
};

static int __init vmgenid_init(void)
{
	return acpi_bus_register_driver(&acpi_vmgenid_driver);
}

static void __exit vmgenid_exit(void)
{
	acpi_bus_unregister_driver(&acpi_vmgenid_driver);
}

module_init(vmgenid_init);
module_exit(vmgenid_exit);

MODULE_AUTHOR("Adrian Catangiu");
MODULE_DESCRIPTION("Virtual Machine Generation ID");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
