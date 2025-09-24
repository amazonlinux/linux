/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ASM_X86_SERPENT_AVX_H
#define ASM_X86_SERPENT_AVX_H

#include <crypto/api.h>
#include <crypto/b128ops.h>
#include <crypto/serpent.h>
#include <linux/types.h>

struct crypto_skcipher;

#define SERPENT_PARALLEL_BLOCKS 8

DECLARE_CRYPTO_API(CONFIG_CRYPTO_SERPENT_AVX_X86_64, serpent_ecb_enc_8way_avx, asmlinkage void,
	(const void *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_SERPENT_AVX_X86_64, serpent_ecb_dec_8way_avx, asmlinkage void,
	(const void *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_SERPENT_AVX_X86_64, serpent_cbc_dec_8way_avx, asmlinkage void,
	(const void *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));

#endif
