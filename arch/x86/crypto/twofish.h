/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ASM_X86_TWOFISH_H
#define ASM_X86_TWOFISH_H

#include <crypto/api.h>
#include <linux/crypto.h>
#include <crypto/twofish.h>
#include <crypto/b128ops.h>

/* regular block cipher functions from twofish_x86_64 module */
DECLARE_CRYPTO_API(CONFIG_CRYPTO_TWOFISH_X86_64, twofish_enc_blk, asmlinkage void,
	(const void *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_TWOFISH_X86_64, twofish_dec_blk, asmlinkage void,
	(const void *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));

/* 3-way parallel cipher functions */
asmlinkage void __twofish_enc_blk_3way(const void *ctx, u8 *dst, const u8 *src,
				       bool xor);
asmlinkage void twofish_dec_blk_3way(const void *ctx, u8 *dst, const u8 *src);

/* helpers from twofish_x86_64-3way module */
extern void twofish_dec_blk_cbc_3way(const void *ctx, u8 *dst, const u8 *src);

#endif /* ASM_X86_TWOFISH_H */
