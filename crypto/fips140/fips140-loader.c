// SPDX-License-Identifier: GPL-2.0-only
/*
 * FIPS 140 Early Loader
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/elf.h>
#include <linux/kthread.h>
#include <linux/wait.h>

extern const u8 _binary_fips140_ko_start[];
EXPORT_SYMBOL_GPL(_binary_fips140_ko_start);
extern const u8 _binary_fips140_ko_end[];
EXPORT_SYMBOL_GPL(_binary_fips140_ko_end);

extern const u8 _binary_fips140_hmac_start[];
EXPORT_SYMBOL_GPL(_binary_fips140_hmac_start);
extern const u8 _binary_fips140_hmac_end[];
EXPORT_SYMBOL_GPL(_binary_fips140_hmac_end);

/* Function to load module from memory */
extern int load_module_mem(const char *mem, size_t size);

static int __init fips_loader_init(void)
{
	const void *ko_mem = _binary_fips140_ko_start;
	size_t ko_size = _binary_fips140_ko_end - _binary_fips140_ko_start;
	void *vmalloc_mem;
	int ret;
	
	// Copy to vmalloc'd memory since load_module expects to free it
	vmalloc_mem = vmalloc(ko_size);
	if (!vmalloc_mem) {
		pr_err("FIPS140 loader: failed to allocate memory\n");
		return -ENOMEM;
	}
	
	memcpy(vmalloc_mem, ko_mem, ko_size);
	
	ret = load_module_mem(vmalloc_mem, ko_size); // Skip signature check
	if (ret)
		panic("FIPS140 loader: module loading error\n");

	vfree(vmalloc_mem); // Free after successful module loading
	return ret;
}

/* FIPS140 synchronization between kernel and module
 *
 * Synchronization levels map kernel initcall levels to FIPS module levels:
 * - Level 0: subsys_initcall (kernel init level 4) - Basic subsystem initialization
 * - Level 1: device_initcall (kernel init level 6) - Device driver initialization  
 * - Level 2: late_initcall (kernel init level 7) - Late system initialization
 *
 * The kernel marks each level complete and waits for the FIPS module to
 * complete the corresponding level before proceeding to ensure proper
 * initialization ordering between kernel crypto and FIPS module.
 */
atomic_t fips140_kernel_level_complete = ATOMIC_INIT(0);
atomic_t fips140_module_level_complete = ATOMIC_INIT(0);

/* Wait queues for efficient synchronization */
DECLARE_WAIT_QUEUE_HEAD(fips140_kernel_wq);
DECLARE_WAIT_QUEUE_HEAD(fips140_module_wq);

void fips140_mark_kernel_level_complete(int level)
{
	atomic_or(1 << level, &fips140_kernel_level_complete);
	wake_up(&fips140_kernel_wq);
}

bool fips140_is_kernel_level_complete(int level)
{
	return atomic_read(&fips140_kernel_level_complete) & (1 << level);
}

bool fips140_is_module_level_complete(int level)
{
	return atomic_read(&fips140_module_level_complete) & (1 << level);
}

void fips140_mark_module_level_complete(int level)
{
	atomic_or(1 << level, &fips140_module_level_complete);
	wake_up(&fips140_module_wq);
}

static int __init fips140_sync_thread(void *data)
{
	pr_info("FIPS 140: starting sync thread\n");
	
	/* Call FIPS loader explicitly */
	int ret = fips_loader_init();
	if (ret)
		panic("FIPS 140: loader initialization failed: %d\n", ret);
	
	pr_info("FIPS 140: sync thread finished\n");
	return 0;
}

void __init start_fips140_loader(void)
{
	struct task_struct *task;
	
	task = kthread_run(fips140_sync_thread, NULL, "fips140_sync");
	if (IS_ERR(task)) {
		panic("FIPS 140: failed to create sync thread\n");
	}
}

void __init wait_until_fips140_level_sync(int level)
{
	/* Map kernel initcall levels to FIPS module levels */
	int fips_level = -1;
	if (level == 3) /* Start FIPS loader thread at arch_initcall_sync level */
		start_fips140_loader(); 
	if (level == 4) /* subsys_initcall */
		fips_level = 0;
	else if (level == 6) /* device_initcall */
		fips_level = 1;
	else if (level == 7) /* late_initcall */
		fips_level = 2;

	if (fips_level >= 0) {
		/* Mark kernel level complete and wait for module level completion */
		fips140_mark_kernel_level_complete(fips_level);
		wait_event(fips140_module_wq, fips140_is_module_level_complete(fips_level));
	}
}

EXPORT_SYMBOL(fips140_kernel_level_complete);
EXPORT_SYMBOL(fips140_module_level_complete);
EXPORT_SYMBOL(fips140_kernel_wq);
EXPORT_SYMBOL(fips140_module_wq);
EXPORT_SYMBOL(fips140_mark_kernel_level_complete);
EXPORT_SYMBOL(fips140_is_kernel_level_complete);
EXPORT_SYMBOL(fips140_is_module_level_complete);
EXPORT_SYMBOL(fips140_mark_module_level_complete);