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
#include <linux/fips.h>

extern const u8 _binary_fips140_ko_start[];
extern const u8 _binary_fips140_ko_end[];
extern const u8 _binary_fips140_hmac_start[];
extern const u8 _binary_fips140_hmac_end[];

#ifdef CONFIG_CRYPTO_FIPS140_DUAL_VERSION
/* For non-FIPS mode: no module signature/HMAC is required,
 * so only include binary start/end address without module sig address */
extern const u8 _binary_nonfips140_ko_start[];
extern const u8 _binary_nonfips140_ko_end[];
#endif

const u8 *_binary_crypto_ko_start;
EXPORT_SYMBOL_GPL(_binary_crypto_ko_start);
const u8 *_binary_crypto_ko_end;
EXPORT_SYMBOL_GPL(_binary_crypto_ko_end);
const u8 *_binary_crypto_hmac_start;
EXPORT_SYMBOL_GPL(_binary_crypto_hmac_start);
const u8 *_binary_crypto_hmac_end;
EXPORT_SYMBOL_GPL(_binary_crypto_hmac_end);

#ifdef CONFIG_DEBUG_INFO_BTF_MODULES
extern const u8 __start_fips140_btf[];
extern const u8 __stop_fips140_btf[];
#ifdef CONFIG_CRYPTO_FIPS140_DUAL_VERSION
extern const u8 __start_nonfips140_btf[];
extern const u8 __stop_nonfips140_btf[];
#endif
const u8 *__start_crypto_btf;
const u8 *__stop_crypto_btf;
#endif

/* Function to load crypto module from memory */
extern int load_crypto_module_mem(const char *mem, size_t size);

static void load_prepare(void)
{
	_binary_crypto_ko_start = _binary_fips140_ko_start;
	_binary_crypto_ko_end = _binary_fips140_ko_end;
	_binary_crypto_hmac_start = _binary_fips140_hmac_start;
	_binary_crypto_hmac_end = _binary_fips140_hmac_end;
	
#ifdef CONFIG_DEBUG_INFO_BTF_MODULES
	__start_crypto_btf = __start_fips140_btf;
	__stop_crypto_btf = __stop_fips140_btf;
#endif

#ifdef CONFIG_CRYPTO_FIPS140_DUAL_VERSION
	if (!fips_enabled) {
		_binary_crypto_ko_start = _binary_nonfips140_ko_start;
		_binary_crypto_ko_end = _binary_nonfips140_ko_end;
		_binary_crypto_hmac_start = NULL;
		_binary_crypto_hmac_end = NULL;

#ifdef CONFIG_DEBUG_INFO_BTF_MODULES
		__start_crypto_btf = __start_nonfips140_btf;
		__stop_crypto_btf = __stop_nonfips140_btf;
#endif
		}
#endif
}

static int fips_loader_init(void)
{
	load_prepare();
	
	const void *ko_mem = _binary_crypto_ko_start;
	size_t ko_size = _binary_crypto_ko_end - _binary_crypto_ko_start;
	void *vmalloc_mem;
	int ret;
	
	// Copy to vmalloc'd memory since load_module expects to free it
	vmalloc_mem = vmalloc(ko_size);
	if (!vmalloc_mem) {
		pr_err("FIPS140 loader: failed to allocate memory\n");
		return -ENOMEM;
	}
	
	memcpy(vmalloc_mem, ko_mem, ko_size);
	
	ret = load_crypto_module_mem(vmalloc_mem, ko_size); // Skip signature check
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

static int fips140_sync_thread(void *data)
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

/*
 * Map kernel initcall levels to FIPS module sync levels:
 *   kernel 3 (arch_initcall_sync)    → fips 0: loader start + module init
 *   kernel 4 (subsys_initcall_sync)  → fips 1: fips initcall level 0 (subsys)
 *   kernel 6 (device_initcall_sync)  → fips 2: fips initcall level 1 (module)
 *   kernel 7 (late_initcall_sync)    → fips 3: fips initcall level 2 (late) + verify_integrity
 */
static int __init fips140_level_to_fips(int level)
{
	if (level == 3) return 0;
	if (level == 4) return 1;
	if (level == 6) return 2;
	if (level == 7) return 3;
	return -1;
}

void __init wait_until_fips140_level_sync(int level)
{
	int fips_level = fips140_level_to_fips(level);

	if (level == 3) {
		pr_err("FIPS 140: sync level %d: starting loader\n", level);
		start_fips140_loader();
	}

	if (fips_level >= 0) {
		pr_err("FIPS 140: sync level %d: waiting module_level %d (current module_level=0x%x)\n",
			level, fips_level,
			atomic_read(&fips140_module_level_complete));
		wait_event(fips140_module_wq, fips140_is_module_level_complete(fips_level));
		pr_err("FIPS 140: sync level %d: module_level %d complete\n", level, fips_level);
	}
}

void __init fips140_mark_kernel_level_done(int level)
{
	int fips_level = fips140_level_to_fips(level);

	if (fips_level >= 0) {
		pr_err("FIPS 140: post level %d: marking kernel_level %d complete\n",
			level, fips_level);
		fips140_mark_kernel_level_complete(fips_level);
	}
}

/*
 * FIPS sync initcalls:
 * - .initcallN-fips140.init: runs AFTER regular initcalls, BEFORE _sync.
 *   Waits for FIPS module to complete this level.
 * - .initcallN-fips140post.init: runs AFTER _sync initcalls.
 *   Marks kernel level complete so FIPS module can proceed to next level.
 */
#define DEFINE_FIPS140_LEVEL_SYNC(lvl, sec_pre, sec_post)		\
	static int __init fips140_sync_level##lvl(void)			\
	{								\
		wait_until_fips140_level_sync(lvl);			\
		return 0;						\
	}								\
	____define_initcall(fips140_sync_level##lvl,			\
		fips140_sync_level##lvl,				\
		__initcall_fips140_sync##lvl, sec_pre);			\
	static int __init fips140_post_level##lvl(void)			\
	{								\
		fips140_mark_kernel_level_done(lvl);			\
		return 0;						\
	}								\
	____define_initcall(fips140_post_level##lvl,			\
		fips140_post_level##lvl,				\
		__initcall_fips140_post##lvl, sec_post)

DEFINE_FIPS140_LEVEL_SYNC(3, ".initcall3-fips140.init", ".initcall3-fips140post.init");
DEFINE_FIPS140_LEVEL_SYNC(4, ".initcall4-fips140.init", ".initcall4-fips140post.init");
DEFINE_FIPS140_LEVEL_SYNC(6, ".initcall6-fips140.init", ".initcall6-fips140post.init");
DEFINE_FIPS140_LEVEL_SYNC(7, ".initcall7-fips140.init", ".initcall7-fips140post.init");

EXPORT_SYMBOL(fips140_kernel_level_complete);
EXPORT_SYMBOL(fips140_module_level_complete);
EXPORT_SYMBOL(fips140_kernel_wq);
EXPORT_SYMBOL(fips140_module_wq);
EXPORT_SYMBOL(fips140_mark_kernel_level_complete);
EXPORT_SYMBOL(fips140_is_kernel_level_complete);
EXPORT_SYMBOL(fips140_is_module_level_complete);
EXPORT_SYMBOL(fips140_mark_module_level_complete);