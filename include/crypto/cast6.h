/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTO_CAST6_H
#define _CRYPTO_CAST6_H

#include <crypto/api.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <crypto/cast_common.h>

#define CAST6_BLOCK_SIZE 16
#define CAST6_MIN_KEY_SIZE 16
#define CAST6_MAX_KEY_SIZE 32

struct cast6_ctx {
	u32 Km[12][4];
	u8 Kr[12][4];
};

DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAST6, __cast6_setkey, int,
	(struct cast6_ctx *ctx, const u8 *key, unsigned int keylen),
	(ctx, key, keylen));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAST6, cast6_setkey, int,
	(struct crypto_tfm *tfm, const u8 *key, unsigned int keylen),
	(tfm, key, keylen));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAST6, __cast6_encrypt, void,
	(const void *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAST6, __cast6_decrypt, void,
	(const void *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));

#endif
