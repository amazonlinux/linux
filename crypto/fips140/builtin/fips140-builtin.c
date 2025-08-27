// SPDX-License-Identifier: GPL-2.0-only
/*
 * FIPS 140 Built-in Support
 *
 * This file provides built-in kernel support for FIPS 140 module tracking.
 * It defines the module pointer that gets set when fips140.ko is loaded.
 */

#include <linux/module.h>

#ifdef CONFIG_CRYPTO_FIPS140_MOD
struct module *fips140_module_ptr = NULL;
EXPORT_SYMBOL_GPL(fips140_module_ptr);
#endif
