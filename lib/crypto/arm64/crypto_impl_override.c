// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Boot-time crypto implementation overrides for FIPS testing (ARM64)
 *
 * When not set, the kernel auto-detects the best available implementation
 * based on CPU features (default behavior, unchanged).
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

#include <linux/init.h>
#include <linux/export.h>

/*
 * Kernel boot parameter: sha256_arm64_impl=<value>
 *
 * Valid values and the implementation they select:
 *   generic - Pure C software implementation (sha256_blocks_generic)
 *   asm     - Scalar ARM64 assembly, no SIMD (sha256_block_data_order)
 *   neon    - NEON/ASIMD assembly (sha256_block_neon)
 *   ce      - ARMv8 Crypto Extensions (sha256h/sha256h2 instructions)
 *
 * Example: add "sha256_arm64_impl=neon" to the kernel command line.
 */
char *sha256_arm64_impl_override;
EXPORT_SYMBOL_GPL(sha256_arm64_impl_override);

static int __init sha256_arm64_impl_setup(char *str)
{
	sha256_arm64_impl_override = str;
	return 1;
}
__setup("sha256_arm64_impl=", sha256_arm64_impl_setup);
