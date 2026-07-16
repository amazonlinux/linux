/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SHA-1 optimized for ARM64
 *
 * Copyright 2025 Google LLC
 */
#include <asm/neon.h>
#include <asm/simd.h>
#include <linux/cpufeature.h>

static __ro_after_init DEFINE_STATIC_KEY_FALSE(have_ce);

asmlinkage size_t __sha1_ce_transform(struct sha1_block_state *state,
				      const u8 *data, size_t nblocks);

static void sha1_blocks(struct sha1_block_state *state,
			const u8 *data, size_t nblocks)
{
	if (static_branch_likely(&have_ce) && likely(may_use_simd())) {
		do {
			size_t rem;

			kernel_neon_begin();
			rem = __sha1_ce_transform(state, data, nblocks);
			kernel_neon_end();
			data += (nblocks - rem) * SHA1_BLOCK_SIZE;
			nblocks = rem;
		} while (nblocks);
	} else {
		sha1_blocks_generic(state, data, nblocks);
	}
}

#define sha1_mod_init_arch sha1_mod_init_arch
static void sha1_mod_init_arch(void)
{
	extern char *sha1_arm64_impl_override;
	const char *requested = sha1_arm64_impl_override;
	const char *impl = requested;
	const char *sel = "generic";
	bool known = false;

	if (impl) {
		bool supported = false;

		if (!strcmp(impl, "generic")) {
			known = true;
			supported = true;
		} else if (!strcmp(impl, "ce")) {
			known = true;
			supported = cpu_have_named_feature(SHA1);
		}

		if (!supported)
			impl = NULL;
	}

	if ((!impl && cpu_have_named_feature(SHA1)) ||
	    (impl && !strcmp(impl, "ce"))) {
		static_branch_enable(&have_ce);
		sel = "CE";
	}
	/* else: have_ce stays disabled and sha1_blocks_generic is used
	 * (impl=="generic", or CPU lacks the SHA1 feature) */

	if (requested) {
		if (impl)
			pr_info("sha1: using %s implementation (forced by sha1_arm64_impl=%s)\n",
				sel, requested);
		else if (known)
			pr_warn("sha1: CPU features unavailable for sha1_arm64_impl=%s; override failed, using %s implementation\n",
				requested, sel);
		else
			pr_warn("sha1: unknown sha1_arm64_impl=%s; override failed, using %s implementation\n",
				requested, sel);
	}
}
