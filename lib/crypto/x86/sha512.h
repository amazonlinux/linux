/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * x86-optimized SHA-512 block function
 *
 * Copyright 2025 Google LLC
 */
#include <asm/fpu/api.h>
#include <linux/static_call.h>

DEFINE_STATIC_CALL(sha512_blocks_x86, sha512_blocks_generic);

#define DEFINE_X86_SHA512_FN(c_fn, asm_fn)                                 \
	asmlinkage void asm_fn(struct sha512_block_state *state,           \
			       const u8 *data, size_t nblocks);            \
	static void c_fn(struct sha512_block_state *state, const u8 *data, \
			 size_t nblocks)                                   \
	{                                                                  \
		if (likely(irq_fpu_usable())) {                            \
			kernel_fpu_begin();                                \
			asm_fn(state, data, nblocks);                      \
			kernel_fpu_end();                                  \
		} else {                                                   \
			sha512_blocks_generic(state, data, nblocks);       \
		}                                                          \
	}

DEFINE_X86_SHA512_FN(sha512_blocks_ssse3, sha512_transform_ssse3);
DEFINE_X86_SHA512_FN(sha512_blocks_avx, sha512_transform_avx);
DEFINE_X86_SHA512_FN(sha512_blocks_avx2, sha512_transform_rorx);

static void sha512_blocks(struct sha512_block_state *state,
			  const u8 *data, size_t nblocks)
{
	static_call(sha512_blocks_x86)(state, data, nblocks);
}

#define sha512_mod_init_arch sha512_mod_init_arch
static void sha512_mod_init_arch(void)
{
	extern char *sha512_x86_impl_override;
	const char *requested = sha512_x86_impl_override;
	const char *impl = requested;
	const char *sel = "generic";
	bool known = false;

	if (impl) {
		bool supported = false;

		if (!strcmp(impl, "generic")) {
			known = true;
			supported = true;
		} else if (!strcmp(impl, "avx2")) {
			known = true;
			supported = cpu_has_xfeatures(XFEATURE_MASK_SSE |
					XFEATURE_MASK_YMM, NULL) &&
				    boot_cpu_has(X86_FEATURE_AVX) &&
				    boot_cpu_has(X86_FEATURE_AVX2) &&
				    boot_cpu_has(X86_FEATURE_BMI2);
		} else if (!strcmp(impl, "avx")) {
			known = true;
			supported = cpu_has_xfeatures(XFEATURE_MASK_SSE |
					XFEATURE_MASK_YMM, NULL) &&
				    boot_cpu_has(X86_FEATURE_AVX);
		} else if (!strcmp(impl, "ssse3")) {
			known = true;
			supported = boot_cpu_has(X86_FEATURE_SSSE3);
		}

		if (!supported)
			impl = NULL;
	}

	if ((!impl && cpu_has_xfeatures(XFEATURE_MASK_SSE |
			XFEATURE_MASK_YMM, NULL) &&
	     boot_cpu_has(X86_FEATURE_AVX) &&
	     boot_cpu_has(X86_FEATURE_AVX2) &&
	     boot_cpu_has(X86_FEATURE_BMI2)) ||
	    (impl && !strcmp(impl, "avx2"))) {
		static_call_update(sha512_blocks_x86, sha512_blocks_avx2);
		sel = "AVX2";
	} else if ((!impl && cpu_has_xfeatures(XFEATURE_MASK_SSE |
			XFEATURE_MASK_YMM, NULL) &&
		    boot_cpu_has(X86_FEATURE_AVX)) ||
		   (impl && !strcmp(impl, "avx"))) {
		static_call_update(sha512_blocks_x86, sha512_blocks_avx);
		sel = "AVX";
	} else if ((!impl && boot_cpu_has(X86_FEATURE_SSSE3)) ||
		   (impl && !strcmp(impl, "ssse3"))) {
		static_call_update(sha512_blocks_x86, sha512_blocks_ssse3);
		sel = "SSSE3";
	}
	/* else: stays at sha512_blocks_generic (default, or impl=="generic") */

	if (requested) {
		if (impl)
			pr_info("sha512: using %s implementation (forced by sha512_x86_impl=%s)\n",
				sel, requested);
		else if (known)
			pr_warn("sha512: CPU features unavailable for sha512_x86_impl=%s; override failed, using %s implementation\n",
				requested, sel);
		else
			pr_warn("sha512: unknown sha512_x86_impl=%s; override failed, using %s implementation\n",
				requested, sel);
	}
}
