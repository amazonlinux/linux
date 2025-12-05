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
extern const u8 _binary_fips140_ko_end[];
extern const u8 _binary_fips140_hmac_start[];
extern const u8 _binary_fips140_hmac_end[];

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
