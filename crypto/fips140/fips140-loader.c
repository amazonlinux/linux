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

extern const u8 _binary_fips140_ko_start[];
extern const u8 _binary_fips140_ko_end[];

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
		goto out;
out:
	if (ret)
		panic("FIPS 140-3 module: loading error\n");

	// Don't free vmalloc_mem here - load_module will handle it
	return ret;
}
arch_initcall_sync(fips_loader_init);
