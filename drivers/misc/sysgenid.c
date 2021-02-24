// SPDX-License-Identifier: GPL-2.0
/*
 * System Generation ID driver
 *
 * Copyright (C) 2020 Amazon. All rights reserved.
 *
 *	Authors:
 *	  Adrian Catangiu <acatan@amazon.com>
 *
 */
#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/minmax.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/random.h>
#include <linux/uuid.h>
#include <linux/sysgenid.h>

struct sysgenid_data {
	unsigned long		map_buf;
	wait_queue_head_t	read_waitq;
	atomic_t		generation_counter;

	unsigned int		watchers;
	atomic_t		outdated_watchers;
	wait_queue_head_t	outdated_waitq;
	spinlock_t		lock;
};
static struct sysgenid_data sysgenid_data;

struct file_data {
	bool tracked_watcher;
	int acked_gen_counter;
};

static int equals_gen_counter(unsigned int counter)
{
	return counter == atomic_read(&sysgenid_data.generation_counter);
}

static void _bump_generation(int min_gen)
{
	unsigned long flags;
	int counter;

	spin_lock_irqsave(&sysgenid_data.lock, flags);
	counter = max(min_gen, 1 + atomic_read(&sysgenid_data.generation_counter));
	atomic_set(&sysgenid_data.generation_counter, counter);
	*((int *) sysgenid_data.map_buf) = counter;
	atomic_set(&sysgenid_data.outdated_watchers, sysgenid_data.watchers);

	wake_up_interruptible(&sysgenid_data.read_waitq);
	wake_up_interruptible(&sysgenid_data.outdated_waitq);
	spin_unlock_irqrestore(&sysgenid_data.lock, flags);
}

void sysgenid_bump_generation(void)
{
	_bump_generation(0);
}
EXPORT_SYMBOL_GPL(sysgenid_bump_generation);

static void put_outdated_watchers(void)
{
	if (atomic_dec_and_test(&sysgenid_data.outdated_watchers))
		wake_up_interruptible(&sysgenid_data.outdated_waitq);
}

static void start_fd_tracking(struct file_data *fdata)
{
	unsigned long flags;

	if (!fdata->tracked_watcher) {
		/* enable tracking this fd as a watcher */
		spin_lock_irqsave(&sysgenid_data.lock, flags);
			fdata->tracked_watcher = 1;
			++sysgenid_data.watchers;
			if (!equals_gen_counter(fdata->acked_gen_counter))
				atomic_inc(&sysgenid_data.outdated_watchers);
		spin_unlock_irqrestore(&sysgenid_data.lock, flags);
	}
}

static void stop_fd_tracking(struct file_data *fdata)
{
	unsigned long flags;

	if (fdata->tracked_watcher) {
		/* stop tracking this fd as a watcher */
		spin_lock_irqsave(&sysgenid_data.lock, flags);
		if (!equals_gen_counter(fdata->acked_gen_counter))
			put_outdated_watchers();
		--sysgenid_data.watchers;
		fdata->tracked_watcher = 0;
		spin_unlock_irqrestore(&sysgenid_data.lock, flags);
	}
}

static int sysgenid_open(struct inode *inode, struct file *file)
{
	struct file_data *fdata = kzalloc(sizeof(struct file_data), GFP_KERNEL);

	if (!fdata)
		return -ENOMEM;
	fdata->tracked_watcher = 0;
	fdata->acked_gen_counter = atomic_read(&sysgenid_data.generation_counter);
	file->private_data = fdata;

	return 0;
}

static int sysgenid_close(struct inode *inode, struct file *file)
{
	struct file_data *fdata = file->private_data;

	stop_fd_tracking(fdata);
	kfree(fdata);

	return 0;
}

static ssize_t sysgenid_read(struct file *file, char __user *ubuf,
		size_t nbytes, loff_t *ppos)
{
	struct file_data *fdata = file->private_data;
	ssize_t ret;
	int gen_counter;

	if (nbytes == 0)
		return 0;
	/* disallow partial reads */
	if (nbytes < sizeof(gen_counter))
		return -EINVAL;

	if (equals_gen_counter(fdata->acked_gen_counter)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		ret = wait_event_interruptible(
			sysgenid_data.read_waitq,
			!equals_gen_counter(fdata->acked_gen_counter)
		);
		if (ret)
			return ret;
	}

	gen_counter = atomic_read(&sysgenid_data.generation_counter);
	ret = copy_to_user(ubuf, &gen_counter, sizeof(gen_counter));
	if (ret)
		return -EFAULT;

	return sizeof(gen_counter);
}

static ssize_t sysgenid_write(struct file *file, const char __user *ubuf,
		size_t count, loff_t *ppos)
{
	struct file_data *fdata = file->private_data;
	unsigned int new_acked_gen;
	unsigned long flags;

	/* disallow partial writes */
	if (count != sizeof(new_acked_gen))
		return -ENOBUFS;
	if (copy_from_user(&new_acked_gen, ubuf, count))
		return -EFAULT;

	spin_lock_irqsave(&sysgenid_data.lock, flags);
	/* wrong gen-counter acknowledged */
	if (!equals_gen_counter(new_acked_gen)) {
		spin_unlock_irqrestore(&sysgenid_data.lock, flags);
		return -EINVAL;
	}
	/* update acked gen-counter if necessary */
	if (!equals_gen_counter(fdata->acked_gen_counter)) {
		fdata->acked_gen_counter = new_acked_gen;
		if (fdata->tracked_watcher)
			put_outdated_watchers();
	}
	spin_unlock_irqrestore(&sysgenid_data.lock, flags);

	return (ssize_t)count;
}

static __poll_t sysgenid_poll(struct file *file, poll_table *wait)
{
	__poll_t mask = 0;
	struct file_data *fdata = file->private_data;

	if (!equals_gen_counter(fdata->acked_gen_counter))
		return EPOLLIN | EPOLLRDNORM;

	poll_wait(file, &sysgenid_data.read_waitq, wait);

	if (!equals_gen_counter(fdata->acked_gen_counter))
		mask = EPOLLIN | EPOLLRDNORM;

	return mask;
}

static long sysgenid_ioctl(struct file *file,
		unsigned int cmd, unsigned long arg)
{
	struct file_data *fdata = file->private_data;
	bool tracking = !!arg;
	unsigned long timeout_ns, min_gen;
	ktime_t until;
	int ret = 0;

	switch (cmd) {
	case SYSGENID_SET_WATCHER_TRACKING:
		if (tracking)
			start_fd_tracking(fdata);
		else
			stop_fd_tracking(fdata);
		break;
	case SYSGENID_WAIT_WATCHERS:
		timeout_ns = arg * NSEC_PER_MSEC;
		until = timeout_ns ? ktime_set(0, timeout_ns) : KTIME_MAX;

		ret = wait_event_interruptible_hrtimeout(
			sysgenid_data.outdated_waitq,
			(!atomic_read(&sysgenid_data.outdated_watchers) ||
					!equals_gen_counter(fdata->acked_gen_counter)),
			until
		);
		if (!equals_gen_counter(fdata->acked_gen_counter))
			ret = -EINTR;
		break;
	case SYSGENID_TRIGGER_GEN_UPDATE:
		if (!checkpoint_restore_ns_capable(current_user_ns()))
			return -EACCES;
		min_gen = arg;
		_bump_generation(min_gen);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int sysgenid_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct file_data *fdata = file->private_data;

	if (vma->vm_pgoff != 0 || vma_pages(vma) > 1)
		return -EINVAL;

	if ((vma->vm_flags & VM_WRITE) != 0)
		return -EPERM;

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_flags &= ~VM_MAYWRITE;
	vma->vm_private_data = fdata;

	return vm_insert_page(vma, vma->vm_start,
			virt_to_page(sysgenid_data.map_buf));
}

static const struct file_operations fops = {
	.owner		= THIS_MODULE,
	.mmap		= sysgenid_mmap,
	.open		= sysgenid_open,
	.release	= sysgenid_close,
	.read		= sysgenid_read,
	.write		= sysgenid_write,
	.poll		= sysgenid_poll,
	.unlocked_ioctl	= sysgenid_ioctl,
};

static struct miscdevice sysgenid_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sysgenid",
	.fops = &fops,
};

static int __init sysgenid_init(void)
{
	int ret;

	sysgenid_data.map_buf = get_zeroed_page(GFP_KERNEL);
	if (!sysgenid_data.map_buf)
		return -ENOMEM;

	atomic_set(&sysgenid_data.generation_counter, 0);
	atomic_set(&sysgenid_data.outdated_watchers, 0);
	init_waitqueue_head(&sysgenid_data.read_waitq);
	init_waitqueue_head(&sysgenid_data.outdated_waitq);
	spin_lock_init(&sysgenid_data.lock);

	ret = misc_register(&sysgenid_misc);
	if (ret < 0) {
		pr_err("misc_register() failed for sysgenid\n");
		goto err;
	}

	return 0;

err:
	free_pages(sysgenid_data.map_buf, 0);
	sysgenid_data.map_buf = 0;

	return ret;
}

static void __exit sysgenid_exit(void)
{
	misc_deregister(&sysgenid_misc);
	free_pages(sysgenid_data.map_buf, 0);
	sysgenid_data.map_buf = 0;
}

module_init(sysgenid_init);
module_exit(sysgenid_exit);

MODULE_AUTHOR("Adrian Catangiu");
MODULE_DESCRIPTION("System Generation ID");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
