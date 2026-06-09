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

/*
 * FIPS140 synchronization between kernel and module.
 *
 * Each level has TWO barriers matching the kernel's initcall ordering:
 *   1. Non-sync barrier (.initcallN-fips140.init):
 *      - Placed after .initcallN.init (regular initcalls)
 *      - Kernel marks level done, waits for module to mark level done
 *   2. Sync barrier (.initcallN-fips140s.init):
 *      - Placed after .initcallNs.init (_sync initcalls)
 *      - Kernel marks sync done, waits for module to mark sync done
 *
 * Module side mirrors this:
 *   - After running .fips_initcallN:  mark module done, wait kernel done
 *   - After running .fips_initcallNs: mark module sync done, wait kernel sync done
 */

#define FIPS_LEVEL_MIN 3
#define FIPS_LEVEL_MAX 7

/* Completion bitmasks: bit N = level N complete */
static atomic_t fips140_kernel_done = ATOMIC_INIT(0);
static atomic_t fips140_module_done = ATOMIC_INIT(0);
static atomic_t fips140_kernel_done_sync = ATOMIC_INIT(0);
static atomic_t fips140_module_done_sync = ATOMIC_INIT(0);

DECLARE_WAIT_QUEUE_HEAD(fips140_kernel_wq);
DECLARE_WAIT_QUEUE_HEAD(fips140_module_wq);

static int fips140_sync_thread(void *data)
{
	int ret = fips_loader_init();
	if (ret)
		panic("FIPS 140: loader initialization failed: %d\n", ret);
	return 0;
}

static void __init start_fips140_loader(void)
{
	struct task_struct *task;

	task = kthread_run(fips140_sync_thread, NULL, "fips140_sync");
	if (IS_ERR(task))
		panic("FIPS 140: failed to create sync thread\n");
}

/* Kernel non-sync barrier: mark kernel done, wait for module done */
static void __init fips140_mark_kernel_wait_module(int level)
{
	if (level == FIPS_LEVEL_MIN)
		start_fips140_loader();

	pr_err("FIPS 140: kernel mark_and_wait(%d)\n", level);
	atomic_or(1 << level, &fips140_kernel_done);
	wake_up(&fips140_kernel_wq);
	wait_event(fips140_module_wq, atomic_read(&fips140_module_done) & (1 << level));
	pr_err("FIPS 140: kernel mark_and_wait(%d) done\n", level);
}

/* Kernel sync barrier: mark kernel sync done, wait for module sync done */
static void __init fips140_mark_kernel_wait_module_sync(int level)
{
	pr_err("FIPS 140: kernel mark_and_wait_sync(%d)\n", level);
	atomic_or(1 << level, &fips140_kernel_done_sync);
	wake_up(&fips140_kernel_wq);
	wait_event(fips140_module_wq, atomic_read(&fips140_module_done_sync) & (1 << level));
	pr_err("FIPS 140: kernel mark_and_wait_sync(%d) done\n", level);
}

/* Module non-sync: mark module done, wait for kernel done */
/* Rootfs completion flag — set after populate_rootfs runs */
static atomic_t fips140_kernel_rootfs_done = ATOMIC_INIT(0);

void fips140_mark_module_wait_kernel(int level)
{
	pr_err("FIPS 140: module mark_and_wait(%d)\n", level);
	atomic_or(1 << level, &fips140_module_done);
	wake_up(&fips140_module_wq);
	wait_event(fips140_kernel_wq, atomic_read(&fips140_kernel_done) & (1 << level));
	pr_err("FIPS 140: module mark_and_wait(%d) done\n", level);
}

/* Module sync: mark module sync done, wait for kernel sync done */
void fips140_mark_module_wait_kernel_sync(int level)
{
	pr_err("FIPS 140: module mark_and_wait_sync(%d)\n", level);
	atomic_or(1 << level, &fips140_module_done_sync);
	wake_up(&fips140_module_wq);
	if (level == 5) {
		/* Also wait for rootfs (runs between level 5 sync and level 6) */
		wait_event(fips140_kernel_wq,
			(atomic_read(&fips140_kernel_done_sync) & (1 << level)) &&
			atomic_read(&fips140_kernel_rootfs_done));
	} else {
		wait_event(fips140_kernel_wq, atomic_read(&fips140_kernel_done_sync) & (1 << level));
	}
	pr_err("FIPS 140: module mark_and_wait_sync(%d) done\n", level);
}

/*
 * FIPS sync initcalls placed in custom linker sections:
 * - .initcallN-fips140.init: between .initcallN.init and .initcallNs.init
 * - .initcallN-fips140s.init: after .initcallNs.init
 */
#define DEFINE_FIPS140_LEVEL_SYNC(lvl, sec_pre, sec_post)		\
	static int __init fips140_pre_level##lvl(void)			\
	{								\
		fips140_mark_kernel_wait_module(lvl);			\
		return 0;						\
	}								\
	____define_initcall(fips140_pre_level##lvl,			\
		fips140_pre_level##lvl,					\
		__initcall_fips140_pre##lvl, sec_pre);			\
	static int __init fips140_post_level##lvl(void)			\
	{								\
		fips140_mark_kernel_wait_module_sync(lvl);		\
		return 0;						\
	}								\
	____define_initcall(fips140_post_level##lvl,			\
		fips140_post_level##lvl,				\
		__initcall_fips140_post##lvl, sec_post)

DEFINE_FIPS140_LEVEL_SYNC(3, ".initcall3-fips140.init", ".initcall3-fips140s.init");
DEFINE_FIPS140_LEVEL_SYNC(4, ".initcall4-fips140.init", ".initcall4-fips140s.init");
DEFINE_FIPS140_LEVEL_SYNC(5, ".initcall5-fips140.init", ".initcall5-fips140s.init");
DEFINE_FIPS140_LEVEL_SYNC(6, ".initcall6-fips140.init", ".initcall6-fips140s.init");
DEFINE_FIPS140_LEVEL_SYNC(7, ".initcall7-fips140.init", ".initcall7-fips140s.init");

/* Mark rootfs complete — placed after populate_rootfs in .initcallrootfs-fips140s.init */
static int __init fips140_rootfs_done(void)
{
	pr_err("FIPS 140: rootfs done\n");
	atomic_set(&fips140_kernel_rootfs_done, 1);
	wake_up(&fips140_kernel_wq);
	return 0;
}
____define_initcall(fips140_rootfs_done, fips140_rootfs_done,
	__initcall_fips140_rootfs_done, ".initcallrootfs-fips140s.init");

EXPORT_SYMBOL(fips140_mark_module_wait_kernel);
EXPORT_SYMBOL(fips140_mark_module_wait_kernel_sync);