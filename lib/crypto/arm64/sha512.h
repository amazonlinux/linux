/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * arm64-optimized SHA-512 block function
 *
 * Copyright 2025 Google LLC
 */
#include <asm/neon.h>
#include <asm/simd.h>
#include <linux/cpufeature.h>
#include <linux/static_call.h>

static __ro_after_init DEFINE_STATIC_KEY_FALSE(have_sha512_insns);

asmlinkage void sha512_block_data_order(struct sha512_block_state *state,
					const u8 *data, size_t nblocks);
asmlinkage size_t __sha512_ce_transform(struct sha512_block_state *state,
					const u8 *data, size_t nblocks);

DEFINE_STATIC_CALL(sha512_blocks_arm64, sha512_block_data_order);

static void sha512_blocks(struct sha512_block_state *state,
			  const u8 *data, size_t nblocks)
{
	if (IS_ENABLED(CONFIG_KERNEL_MODE_NEON) &&
	    static_branch_likely(&have_sha512_insns) &&
	    likely(may_use_simd())) {
		do {
			size_t rem;

			kernel_neon_begin();
			rem = __sha512_ce_transform(state, data, nblocks);
			kernel_neon_end();
			data += (nblocks - rem) * SHA512_BLOCK_SIZE;
			nblocks = rem;
		} while (nblocks);
	} else {
		static_call(sha512_blocks_arm64)(state, data, nblocks);
	}
}

#ifdef CONFIG_KERNEL_MODE_NEON
#define sha512_mod_init_arch sha512_mod_init_arch
static void sha512_mod_init_arch(void)
{
	extern char *sha512_arm64_impl_override;
	const char *requested = sha512_arm64_impl_override;
	const char *impl = requested;
	const char *sel = "scalar asm";
	bool known = false;

	if (impl) {
		bool supported = false;

		if (!strcmp(impl, "generic") || !strcmp(impl, "asm")) {
			known = true;
			supported = true;
		} else if (!strcmp(impl, "ce")) {
			known = true;
			supported = cpu_have_named_feature(SHA512);
		}

		if (!supported)
			impl = NULL;
	}

	if ((!impl && cpu_have_named_feature(SHA512)) ||
	    (impl && !strcmp(impl, "ce"))) {
		static_branch_enable(&have_sha512_insns);
		sel = "CE";
	} else if (impl && !strcmp(impl, "generic")) {
		static_call_update(sha512_blocks_arm64,
				   sha512_blocks_generic);
		sel = "generic";
	}

	if (requested) {
		if (impl)
			pr_info("sha512: using %s implementation (forced by sha512_arm64_impl=%s)\n",
				sel, requested);
		else if (known)
			pr_warn("sha512: CPU features unavailable for sha512_arm64_impl=%s; override failed, using %s implementation\n",
				requested, sel);
		else
			pr_warn("sha512: unknown sha512_arm64_impl=%s; override failed, using %s implementation\n",
				requested, sel);
	}
}
#endif /* CONFIG_KERNEL_MODE_NEON */
