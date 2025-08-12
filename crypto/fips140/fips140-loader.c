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
extern int load_module_mem(const char *mem, size_t size, bool skip_sig_check);

static int __init fips140_early_load(void)
{
	const void *ko_mem = _binary_fips140_ko_start;
	size_t ko_size = _binary_fips140_ko_end - _binary_fips140_ko_start;
	void *vmalloc_mem;
	Elf64_Ehdr *ehdr;
	int ret;
	
	pr_info("FIPS140 loader: loading embedded module (size=%zu)\n", ko_size);
	
	// Check if it's a valid ELF file
	ehdr = (Elf64_Ehdr *)ko_mem;
	if (ko_size < sizeof(Elf64_Ehdr) || 
	    memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		pr_err("FIPS140 loader: invalid ELF header\n");
		return -EINVAL;
	}
	
	pr_info("FIPS140 loader: ELF magic: %02x %02x %02x %02x\n",
		ehdr->e_ident[0], ehdr->e_ident[1], ehdr->e_ident[2], ehdr->e_ident[3]);
	
	// Copy to vmalloc'd memory since load_module expects to free it
	vmalloc_mem = vmalloc(ko_size);
	if (!vmalloc_mem) {
		pr_err("FIPS140 loader: failed to allocate memory\n");
		return -ENOMEM;
	}
	
	memcpy(vmalloc_mem, ko_mem, ko_size);
	
	ret = load_module_mem(vmalloc_mem, ko_size, true); // Skip signature check
	pr_info("FIPS140 loader: load_module_mem returned %d\n", ret);
	
	// Don't free vmalloc_mem here - load_module will handle it
	return 0;
}

late_initcall(fips140_early_load);
