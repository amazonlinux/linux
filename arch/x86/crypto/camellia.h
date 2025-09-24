/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ASM_X86_CAMELLIA_H
#define ASM_X86_CAMELLIA_H

#include <crypto/api.h>
#include <crypto/b128ops.h>
#include <linux/crypto.h>
#include <linux/kernel.h>

#define CAMELLIA_MIN_KEY_SIZE	16
#define CAMELLIA_MAX_KEY_SIZE	32
#define CAMELLIA_BLOCK_SIZE	16
#define CAMELLIA_TABLE_BYTE_LEN	272
#define CAMELLIA_PARALLEL_BLOCKS 2

struct crypto_skcipher;

struct camellia_ctx {
	u64 key_table[CAMELLIA_TABLE_BYTE_LEN / sizeof(u64)];
	u32 key_length;
};

DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAMELLIA_X86_64, __camellia_setkey, int,
	(struct camellia_ctx *cctx, const unsigned char *key, unsigned int key_len),
	(cctx, key, key_len));

/* regular block cipher functions */
DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAMELLIA_X86_64, __camellia_enc_blk, asmlinkage void,
	(const void *ctx, u8 *dst, const u8 *src, bool xor),
	(ctx, dst, src, xor));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAMELLIA_X86_64, camellia_dec_blk, asmlinkage void,
	(const void *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));

/* 2-way parallel cipher functions */
DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAMELLIA_X86_64, __camellia_enc_blk_2way, asmlinkage void,
	(const void *ctx, u8 *dst, const u8 *src, bool xor),
	(ctx, dst, src, xor));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAMELLIA_X86_64, camellia_dec_blk_2way, asmlinkage void,
	(const void *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));

/* 16-way parallel cipher functions (avx/aes-ni) */
DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAMELLIA_AESNI_AVX_X86_64, camellia_ecb_enc_16way, asmlinkage void,
	(const void *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAMELLIA_AESNI_AVX_X86_64, camellia_ecb_dec_16way, asmlinkage void,
	(const void *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAMELLIA_AESNI_AVX_X86_64, camellia_cbc_dec_16way, asmlinkage void,
	(const void *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));

static inline void camellia_enc_blk(const void *ctx, u8 *dst, const u8 *src)
{
	__camellia_enc_blk(ctx, dst, src, false);
}

static inline void camellia_enc_blk_xor(const void *ctx, u8 *dst, const u8 *src)
{
	__camellia_enc_blk(ctx, dst, src, true);
}

static inline void camellia_enc_blk_2way(const void *ctx, u8 *dst,
					 const u8 *src)
{
	__camellia_enc_blk_2way(ctx, dst, src, false);
}

static inline void camellia_enc_blk_xor_2way(const void *ctx, u8 *dst,
					     const u8 *src)
{
	__camellia_enc_blk_2way(ctx, dst, src, true);
}

/* glue helpers */
DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAMELLIA_X86_64, camellia_decrypt_cbc_2way, void,
	(const void *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));

#endif /* ASM_X86_CAMELLIA_H */
