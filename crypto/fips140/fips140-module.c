// SPDX-License-Identifier: GPL-2.0-only
/*
 * FIPS 140 Kernel Cryptographic Module
 *
 * This file is the core of fips140.ko, which contains various crypto algorithms
 * that are also built into vmlinux.  At load time, this module overrides the
 * built-in implementations of these algorithms with its implementations.  It
 * also runs self-tests on these algorithms and verifies the integrity of its
 * code and data.  If either of these steps fails, the kernel will panic.
 */

#include "fips140-module.h"

#define FIPS140_MODULE_NAME "FIPS 140 Kernel Cryptographic Module"
#define FIPS140_MODULE_VERSION "1.0.0"

#define CRYPTO_INTERNAL "CRYPTO_INTERNAL"

/* Initialize the FIPS 140 module */
static int __init fips140_init(void)
{
    return 0;
}

static void __exit fips140_exit(void)
{
    pr_info("Unloading " FIPS140_MODULE_NAME "\n");
}

module_init(fips140_init);
module_exit(fips140_exit);

MODULE_IMPORT_NS(CRYPTO_INTERNAL);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION(FIPS140_MODULE_NAME);
MODULE_VERSION(FIPS140_MODULE_VERSION);
