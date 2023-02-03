// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Driver for Broadcom MPI3 Storage Controllers
 *
 * Copyright (C) 2017-2022 Broadcom Inc.
 *  (mailto: mpi3mr-linuxdrv.pdl@broadcom.com)
 *
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/compat.h>
#include <linux/uio.h>

#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>


#include "mpi3mr.h"

#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>

struct dentry *mpi3mr_dbgfs_root;

struct mpi3mr_debugfs_buffer {
	void *buf;
	u32 len;
};

static ssize_t
mpi3mr_debugfs_read(struct file *filp, char __user *ubuf, size_t cnt,
	loff_t *ppos)

{
	struct mpi3mr_debugfs_buffer *debug = filp->private_data;

	if (!debug || !debug->buf)
		return 0;

	return simple_read_from_buffer(ubuf, cnt, ppos, debug->buf, debug->len);
}

static int
mpi3mr_debugfs_dmesg_open(struct inode *inode, struct file *file)
{
	struct mpi3mr_ioc *mrioc = inode->i_private;
	struct mpi3mr_debugfs_buffer *debug;

	if (!mrioc->drv_diag_buffer)
		return -EPERM;

	debug = kzalloc(sizeof(struct mpi3mr_debugfs_buffer), GFP_KERNEL);
	if (!debug)
		return -ENOMEM;

	debug->buf = (void *)mrioc->drv_diag_buffer + sizeof(struct mpi3_driver_buffer_header);
	debug->len = mrioc->drv_diag_buffer_sz - sizeof(struct mpi3_driver_buffer_header);

	file->private_data = debug;

	return 0;
}

static int
mpi3mr_debugfs_uefi_logs_open(struct inode *inode, struct file *file)
{
	struct mpi3mr_ioc *mrioc = inode->i_private;
	struct mpi3mr_debugfs_buffer *debug;

	if (!mrioc->uefi_logs)
		return -EPERM;

	debug = kzalloc(sizeof(struct mpi3mr_debugfs_buffer), GFP_KERNEL);
	if (!debug)
		return -ENOMEM;

	debug->buf = (void *)mrioc->uefi_logs;
	debug->len = mrioc->uefi_logs_sz;

	file->private_data = debug;

	return 0;
}
static int
mpi3mr_debugfs_release(struct inode *inode, struct file *file)
{
	struct mpi3mr_debug_buffer *debug = file->private_data;

	if (!debug)
		return 0;

	file->private_data = NULL;
	kfree(debug);
	return 0;
}

static const struct file_operations mpi3mr_debugfs_dmesg_fops = {
	.owner		= THIS_MODULE,
	.open           = mpi3mr_debugfs_dmesg_open,
	.read           = mpi3mr_debugfs_read,
	.release        = mpi3mr_debugfs_release,
};

static const struct file_operations mpi3mr_debugfs_uefi_logs_fops = {
	.owner		= THIS_MODULE,
	.open           = mpi3mr_debugfs_uefi_logs_open,
	.read           = mpi3mr_debugfs_read,
	.release        = mpi3mr_debugfs_release,
};

/*
 * mpi3mr_init_debugfs :	Create debugfs root for mpi3mr driver
 */
void mpi3mr_init_debugfs(void)
{
	mpi3mr_dbgfs_root = debugfs_create_dir(MPI3MR_DRIVER_NAME, NULL);
	if (!mpi3mr_dbgfs_root)
		pr_info("Cannot create debugfs root\n");
}

/*
 * mpi3mr_exit_debugfs :	Remove debugfs root for mpi3mr driver
 */
void mpi3mr_exit_debugfs(void)
{
	debugfs_remove_recursive(mpi3mr_dbgfs_root);
}

/*
 * mpi3mr_setup_debugfs :	Setup debugfs per adapter
 * mrioc:			Soft instance of adapter
 */
void
mpi3mr_setup_debugfs(struct mpi3mr_ioc *mrioc)
{
	char name[64];
	int i;

	snprintf(name, sizeof(name), "scsi_host%d", mrioc->shost->host_no);

	if (!mrioc->dbgfs_adapter) {
		mrioc->dbgfs_adapter =
		    debugfs_create_dir(name, mpi3mr_dbgfs_root);

		if (!mrioc->dbgfs_adapter) {
			ioc_err(mrioc,
			    "failed to create per adapter debugfs directory\n");
			return;
		}
	}

	for (i = 0; i < mrioc->num_queues; i++) {
		snprintf(name, sizeof(name), "queue%d", mrioc->req_qinfo[i].qid);
		mrioc->req_qinfo[i].dbgfs_req_queue =
		    debugfs_create_dir(name, mrioc->dbgfs_adapter);

		if (!mrioc->req_qinfo[i].dbgfs_req_queue) {
			ioc_err(mrioc,
			    "failed to create per request queue debugfs directory\n");
			debugfs_remove_recursive(mrioc->dbgfs_adapter);
			mrioc->dbgfs_adapter = NULL;
			return;
		}

		debugfs_create_u32("qfull_instances", 0444,
		    mrioc->req_qinfo[i].dbgfs_req_queue,
		    &mrioc->req_qinfo[i].qfull_instances);

		debugfs_create_u64("qfull_io_count", 0644,
		    mrioc->req_qinfo[i].dbgfs_req_queue,
		    &mrioc->req_qinfo[i].qfull_io_count);
	}

	/* This interface to dump system logs in host space is for test/verify purpose only */
	snprintf(name, sizeof(name), "dmesg");
	mrioc->dmesg_dump =
		debugfs_create_file(name, 0444,
				mrioc->dbgfs_adapter,
				mrioc, &mpi3mr_debugfs_dmesg_fops);
	if (!mrioc->dmesg_dump) {
		ioc_err(mrioc, "cannot create dmesg debugfs file\n");
		debugfs_remove(mrioc->dbgfs_adapter);
	}

	snprintf(name, sizeof(name), "uefi_logs");
	mrioc->uefi_logs_dump =
		debugfs_create_file(name, 0444,
				mrioc->dbgfs_adapter,
				mrioc, &mpi3mr_debugfs_uefi_logs_fops);
	if (!mrioc->uefi_logs_dump) {
		ioc_err(mrioc, "cannot create uefi debugfs file\n");
		debugfs_remove(mrioc->dbgfs_adapter);
	}
}

/*
 * mpi3mr_destroy_debugfs :	Destroy debugfs per adapter
 * mrioc:			Soft instance of adapter
 */
void mpi3mr_destroy_debugfs(struct mpi3mr_ioc *mrioc)
{
	debugfs_remove_recursive(mrioc->dbgfs_adapter);
	mrioc->dbgfs_adapter = NULL;
}

#else
void mpi3mr_init_debugfs(void)
{
}
void mpi3mr_exit_debugfs(void)
{
}
void mpi3mr_setup_debugfs(struct mpi3mr_ioc *mrioc)
{
}
void mpi3mr_destroy_debugfs(struct mpi3mr_ioc *mrioc)
{
}
#endif /*CONFIG_DEBUG_FS*/
