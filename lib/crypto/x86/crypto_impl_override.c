// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Boot-time crypto implementation overrides for FIPS testing (x86)
 *
 * When not set, the kernel auto-detects the best available implementation
 * based on CPU features (default behavior, unchanged).
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

#include <linux/init.h>
#include <linux/export.h>

/*
 * Kernel boot parameter: sha256_x86_impl=<value>
 *
 * Valid values and the implementation they select:
 *   generic - Pure C software implementation (sha256_blocks_generic)
 *   ssse3   - SSSE3 assembly (sha256_transform_ssse3)
 *   avx     - AVX assembly (sha256_transform_avx)
 *   avx2    - AVX2+BMI2 assembly (sha256_transform_rorx)
 *   ni      - SHA-NI instructions (sha256_ni_transform)
 *
 * Example: add "sha256_x86_impl=ssse3" to the kernel command line.
 */
char *sha256_x86_impl_override;
EXPORT_SYMBOL_GPL(sha256_x86_impl_override);

static int __init sha256_x86_impl_setup(char *str)
{
	sha256_x86_impl_override = str;
	return 1;
}
__setup("sha256_x86_impl=", sha256_x86_impl_setup);
