/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTO_CAST5_H
#define _CRYPTO_CAST5_H

#include <crypto/api.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <crypto/cast_common.h>

#define CAST5_BLOCK_SIZE 8
#define CAST5_MIN_KEY_SIZE 5
#define CAST5_MAX_KEY_SIZE 16

struct cast5_ctx {
	u32 Km[16];
	u8 Kr[16];
	int rr;	/* rr ? rounds = 12 : rounds = 16; (rfc 2144) */
};

DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAST5, cast5_setkey, int,
	(struct crypto_tfm *tfm, const u8 *key, unsigned int keylen),
	(tfm, key, keylen));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAST5, __cast5_encrypt, void,
	(struct cast5_ctx *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_CAST5, __cast5_decrypt, void,
	(struct cast5_ctx *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));

#endif
