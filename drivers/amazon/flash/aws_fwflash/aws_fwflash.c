// SPDX-License-Identifier: GPL-2.0
/*
 * aws_fwflash - Kernel module for AWS firmware flash operations
 *
 * Provides a character device (/dev/aws_fwflash) with IOCTL commands for
 * triggering Software Management Interrupts (SMI) and mapping physical memory
 * regions, replacing the deprecated /dev/mem and ioperm() mechanisms.
 *
 * Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/capability.h>
#include <linux/irqflags.h>

#include "aws_fwflash_ioctl.h"

#define DRIVER_NAME	"aws_fwflash"
#define DRIVER_VERSION	"1.0.0"
#define DEVICE_NAME	"aws_fwflash"

/* Module parameter: configurable SMI IO port (default 0xB2) */
static unsigned short smi_port = 0xB2;
module_param(smi_port, ushort, 0444);
MODULE_PARM_DESC(smi_port, "SMI IO port address (default: 0xB2)");

/* Per-mapping tracking entry */
struct phys_mapping {
	struct list_head list;
	uint64_t phys_addr;
	uint64_t size;
	void __iomem *virt_addr;
};

/* Per-device state */
struct aws_fwflash_dev {
	struct cdev cdev;
	struct device *device;
	struct class *class;
	struct mutex lock;
	atomic_t open_count;
	struct list_head mappings;
	int major;
};

static struct aws_fwflash_dev aws_fwflash_device;

/* Forward declarations for file operations */
static int aws_fwflash_open(struct inode *inode, struct file *filp);
static int aws_fwflash_release(struct inode *inode, struct file *filp);
static long aws_fwflash_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long arg);

static const struct file_operations aws_fwflash_fops = {
	.owner		= THIS_MODULE,
	.open		= aws_fwflash_open,
	.release	= aws_fwflash_release,
	.unlocked_ioctl	= aws_fwflash_ioctl,
};

/**
 * aws_fwflash_open - Open handler for /dev/aws_fwflash
 *
 * Enforces CAP_SYS_RAWIO capability check and exclusive access (only one
 * process may hold the device open at a time).
 */
static int aws_fwflash_open(struct inode *inode, struct file *filp)
{
	/* Require CAP_SYS_RAWIO for hardware access */
	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;

	/* Enforce exclusive access: only one opener at a time */
	if (atomic_cmpxchg(&aws_fwflash_device.open_count, 0, 1) != 0)
		return -EBUSY;

	filp->private_data = &aws_fwflash_device;
	return 0;
}

/**
 * aws_fwflash_release - Release handler for /dev/aws_fwflash
 *
 * Unmaps all active physical memory mappings associated with this file
 * descriptor and resets the exclusive access lock.
 */
static int aws_fwflash_release(struct inode *inode, struct file *filp)
{
	struct phys_mapping *mapping, *tmp;

	/* Unmap all active mappings */
	mutex_lock(&aws_fwflash_device.lock);
	list_for_each_entry_safe(mapping, tmp, &aws_fwflash_device.mappings, list) {
		if (mapping->virt_addr)
			memunmap((void *)mapping->virt_addr);
		list_del(&mapping->list);
		kfree(mapping);
	}
	mutex_unlock(&aws_fwflash_device.lock);

	/* Release exclusive access */
	atomic_set(&aws_fwflash_device.open_count, 0);

	return 0;
}

/**
 * smi_trigger - Handle AWS_FWFLASH_IOCTL_SMI command
 * @arg: Userspace pointer to struct aws_fwflash_smi_args
 *
 * Validates the port, disables local interrupts, executes the outb instruction
 * with the specified command and port, captures output registers, re-enables
 * interrupts, and copies results back to userspace.
 *
 * Returns 0 on success, negative errno on failure.
 */
static long smi_trigger(unsigned long arg)
{
	struct aws_fwflash_smi_args args;
	unsigned long flags;

	if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
		return -EFAULT;

	/* Validate port matches the configured SMI port */
	if (args.port != smi_port)
		return -EINVAL;

	pr_debug("SMI trigger: cmd=0x%04x port=0x%04x ecx=0x%08x\n",
		 args.command, args.port, args.ecx_in);

	local_irq_save(flags);

	asm volatile("outb %%al, %%dx"
		: "=a"(args.eax_out), "=b"(args.ebx_out),
		  "=c"(args.ecx_out), "=d"(args.edx_out)
		: "a"((uint16_t)args.command), "c"(args.ecx_in),
		  "d"(args.port)
	);

	local_irq_restore(flags);

	if (copy_to_user((void __user *)arg, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}

/**
 * map_phys - Handle AWS_FWFLASH_IOCTL_MAP_PHYS command
 * @arg: Userspace pointer to struct aws_fwflash_phys_region
 *
 * Maps a physical memory region into kernel virtual address space.
 * Tries memremap() first (preferred for normal memory), falls back to ioremap().
 */
static long map_phys(unsigned long arg)
{
	struct aws_fwflash_phys_region region;
	struct phys_mapping *mapping;
	void *vaddr;

	if (copy_from_user(&region, (void __user *)arg, sizeof(region)))
		return -EFAULT;

	if (!region.phys_addr)
		return -EINVAL;

	if (!region.size)
		return -EINVAL;

	/* Allocate tracking entry */
	mapping = kzalloc(sizeof(*mapping), GFP_KERNEL);
	if (!mapping)
		return -ENOMEM;

	/* Try memremap first (preferred for normal memory) */
	vaddr = memremap(region.phys_addr, region.size, MEMREMAP_WB);
	if (!vaddr) {
		/* Fall back to ioremap for MMIO regions */
		vaddr = ioremap(region.phys_addr, region.size);
		if (!vaddr) {
			pr_err("failed to map phys 0x%llx size 0x%llx\n",
			       region.phys_addr, region.size);
			kfree(mapping);
			return -ENOMEM;
		}
	}

	mapping->phys_addr = region.phys_addr;
	mapping->size = region.size;
	mapping->virt_addr = vaddr;

	mutex_lock(&aws_fwflash_device.lock);
	list_add(&mapping->list, &aws_fwflash_device.mappings);
	mutex_unlock(&aws_fwflash_device.lock);

	return 0;
}

/**
 * unmap_phys - Handle AWS_FWFLASH_IOCTL_UNMAP_PHYS command
 * @arg: Userspace pointer to struct aws_fwflash_phys_region
 *
 * Releases the kernel mapping for the specified physical memory region.
 */
static long unmap_phys(unsigned long arg)
{
	struct aws_fwflash_phys_region region;
	struct phys_mapping *mapping, *tmp;
	int found = 0;

	if (copy_from_user(&region, (void __user *)arg, sizeof(region)))
		return -EFAULT;

	mutex_lock(&aws_fwflash_device.lock);
	list_for_each_entry_safe(mapping, tmp, &aws_fwflash_device.mappings, list) {
		if (mapping->phys_addr == region.phys_addr) {
			if (mapping->virt_addr)
				memunmap((void *)mapping->virt_addr);
			list_del(&mapping->list);
			kfree(mapping);
			found = 1;
			break;
		}
	}
	mutex_unlock(&aws_fwflash_device.lock);

	if (!found)
		return -EINVAL;

	return 0;
}

/**
 * find_mapping - Look up an existing mapping by physical address
 * @phys_addr: Physical address to search for
 *
 * Must be called with aws_fwflash_device.lock held.
 * Returns the matching phys_mapping entry, or NULL if not found.
 */
static struct phys_mapping *find_mapping(uint64_t phys_addr)
{
	struct phys_mapping *mapping;

	list_for_each_entry(mapping, &aws_fwflash_device.mappings, list) {
		if (mapping->phys_addr == phys_addr)
			return mapping;
	}
	return NULL;
}

/**
 * read_phys - Handle AWS_FWFLASH_IOCTL_READ_PHYS command
 * @arg: Userspace pointer to struct aws_fwflash_phys_io
 *
 * Copies data from a physical memory region to a userspace buffer.
 * If the region is already mapped via MAP_PHYS, uses the existing mapping.
 * Otherwise, maps on demand, performs the copy, and unmaps.
 *
 * Returns 0 on success, negative errno on failure.
 */
static long read_phys(unsigned long arg)
{
	struct aws_fwflash_phys_io io;
	struct phys_mapping *mapping;
	void __iomem *vaddr = NULL;
	void *kbuf;
	int on_demand = 0;
	long ret = 0;

	if (copy_from_user(&io, (void __user *)arg, sizeof(io)))
		return -EFAULT;

	if (!io.phys_addr || !io.size)
		return -EINVAL;

	/* Allocate kernel bounce buffer */
	kbuf = kvmalloc(io.size, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	mutex_lock(&aws_fwflash_device.lock);

	/* Look up existing mapping */
	mapping = find_mapping(io.phys_addr);
	if (mapping) {
		vaddr = mapping->virt_addr;
	} else {
		/* Map on demand */
		vaddr = memremap(io.phys_addr, io.size, MEMREMAP_WB);
		if (!vaddr)
			vaddr = ioremap(io.phys_addr, io.size);
		if (!vaddr) {
			mutex_unlock(&aws_fwflash_device.lock);
			kvfree(kbuf);
			return -ENOMEM;
		}
		on_demand = 1;
	}

	/* Copy from physical memory to kernel buffer */
	memcpy_fromio(kbuf, vaddr, io.size);

	mutex_unlock(&aws_fwflash_device.lock);

	/* Copy from kernel buffer to userspace */
	if (copy_to_user((void __user *)io.user_buf, kbuf, io.size))
		ret = -EFAULT;

	kvfree(kbuf);

	/* Unmap if we mapped on demand */
	if (on_demand)
		memunmap((void *)vaddr);

	return ret;
}

/**
 * write_phys - Handle AWS_FWFLASH_IOCTL_WRITE_PHYS command
 * @arg: Userspace pointer to struct aws_fwflash_phys_io
 *
 * Copies data from a userspace buffer to a physical memory region.
 * If the region is already mapped via MAP_PHYS, uses the existing mapping.
 * Otherwise, maps on demand, performs the copy, and unmaps.
 *
 * Returns 0 on success, negative errno on failure.
 */
static long write_phys(unsigned long arg)
{
	struct aws_fwflash_phys_io io;
	struct phys_mapping *mapping;
	void __iomem *vaddr = NULL;
	void *kbuf;
	int on_demand = 0;

	if (copy_from_user(&io, (void __user *)arg, sizeof(io)))
		return -EFAULT;

	if (!io.phys_addr || !io.size)
		return -EINVAL;

	/* Allocate kernel bounce buffer */
	kbuf = kvmalloc(io.size, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	/* Copy from userspace to kernel buffer first */
	if (copy_from_user(kbuf, (void __user *)io.user_buf, io.size)) {
		kvfree(kbuf);
		return -EFAULT;
	}

	mutex_lock(&aws_fwflash_device.lock);

	/* Look up existing mapping */
	mapping = find_mapping(io.phys_addr);
	if (mapping) {
		vaddr = mapping->virt_addr;
	} else {
		/* Map on demand */
		vaddr = memremap(io.phys_addr, io.size, MEMREMAP_WB);
		if (!vaddr)
			vaddr = ioremap(io.phys_addr, io.size);
		if (!vaddr) {
			mutex_unlock(&aws_fwflash_device.lock);
			kvfree(kbuf);
			return -ENOMEM;
		}
		on_demand = 1;
	}

	/* Copy from kernel buffer to physical memory */
	memcpy_toio(vaddr, kbuf, io.size);

	mutex_unlock(&aws_fwflash_device.lock);

	kvfree(kbuf);

	/* Unmap if we mapped on demand */
	if (on_demand)
		memunmap((void *)vaddr);

	return 0;
}

static long aws_fwflash_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long arg)
{
	switch (cmd) {
	case AWS_FWFLASH_IOCTL_SMI:
		return smi_trigger(arg);
	case AWS_FWFLASH_IOCTL_MAP_PHYS:
		return map_phys(arg);
	case AWS_FWFLASH_IOCTL_READ_PHYS:
		return read_phys(arg);
	case AWS_FWFLASH_IOCTL_WRITE_PHYS:
		return write_phys(arg);
	case AWS_FWFLASH_IOCTL_UNMAP_PHYS:
		return unmap_phys(arg);
	default:
		return -ENOTTY;
	}
}

/**
 * unmap_all_mappings - Release all active physical memory mappings
 *
 * Called during module exit to ensure no mappings are leaked.
 * Must be called with aws_fwflash_device.lock held.
 */
static void unmap_all_mappings(void)
{
	struct phys_mapping *mapping, *tmp;

	list_for_each_entry_safe(mapping, tmp, &aws_fwflash_device.mappings, list) {
		if (mapping->virt_addr)
			memunmap((void *)mapping->virt_addr);
		list_del(&mapping->list);
		kfree(mapping);
	}
}

/**
 * aws_fwflash_devnode - Set device node permissions to 0600
 */
static char *aws_fwflash_devnode(const struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0600;
	return NULL;
}

static int __init aws_fwflash_init(void)
{
	int ret;
	dev_t devno;

	/* Allocate a dynamic major number */
	ret = alloc_chrdev_region(&devno, 0, 1, DRIVER_NAME);
	if (ret < 0) {
		pr_err("failed to allocate chrdev region: %d\n", ret);
		return ret;
	}
	aws_fwflash_device.major = MAJOR(devno);

	/* Create device class */
	aws_fwflash_device.class = class_create(DRIVER_NAME);
	if (IS_ERR(aws_fwflash_device.class)) {
		ret = PTR_ERR(aws_fwflash_device.class);
		pr_err("failed to create device class: %d\n", ret);
		goto err_unregister_chrdev;
	}
	aws_fwflash_device.class->devnode = aws_fwflash_devnode;

	/* Initialize cdev */
	cdev_init(&aws_fwflash_device.cdev, &aws_fwflash_fops);
	aws_fwflash_device.cdev.owner = THIS_MODULE;

	ret = cdev_add(&aws_fwflash_device.cdev, devno, 1);
	if (ret < 0) {
		pr_err("failed to add cdev: %d\n", ret);
		goto err_destroy_class;
	}

	/* Create device node at /dev/aws_fwflash */
	aws_fwflash_device.device = device_create(aws_fwflash_device.class, NULL,
					       devno, NULL, DEVICE_NAME);
	if (IS_ERR(aws_fwflash_device.device)) {
		ret = PTR_ERR(aws_fwflash_device.device);
		pr_err("failed to create device: %d\n", ret);
		goto err_cdev_del;
	}

	/* Initialize internal state */
	mutex_init(&aws_fwflash_device.lock);
	atomic_set(&aws_fwflash_device.open_count, 0);
	INIT_LIST_HEAD(&aws_fwflash_device.mappings);

	pr_info("v%s loaded, device registered at /dev/%s (major %d, smi_port=0x%04X)\n",
		DRIVER_VERSION, DEVICE_NAME, aws_fwflash_device.major, smi_port);

	return 0;

err_cdev_del:
	cdev_del(&aws_fwflash_device.cdev);
err_destroy_class:
	class_destroy(aws_fwflash_device.class);
err_unregister_chrdev:
	unregister_chrdev_region(devno, 1);
	return ret;
}

static void __exit aws_fwflash_exit(void)
{
	dev_t devno = MKDEV(aws_fwflash_device.major, 0);

	/* Unmap all active mappings */
	mutex_lock(&aws_fwflash_device.lock);
	unmap_all_mappings();
	mutex_unlock(&aws_fwflash_device.lock);

	/* Tear down device infrastructure */
	device_destroy(aws_fwflash_device.class, devno);
	cdev_del(&aws_fwflash_device.cdev);
	class_destroy(aws_fwflash_device.class);
	unregister_chrdev_region(devno, 1);

	pr_info("v%s unloaded, device /dev/%s removed\n",
		DRIVER_VERSION, DEVICE_NAME);
}

module_init(aws_fwflash_init);
module_exit(aws_fwflash_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Amazon.com, Inc.");
MODULE_DESCRIPTION("AWS firmware flash kernel module for SMI triggering and physical memory access");
