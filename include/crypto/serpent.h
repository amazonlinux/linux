/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common values for serpent algorithms
 */

#ifndef _CRYPTO_SERPENT_H
#define _CRYPTO_SERPENT_H

#include <crypto/api.h>
#include <linux/types.h>
#include <linux/crypto.h>

#define SERPENT_MIN_KEY_SIZE		  0
#define SERPENT_MAX_KEY_SIZE		 32
#define SERPENT_EXPKEY_WORDS		132
#define SERPENT_BLOCK_SIZE		 16

struct serpent_ctx {
	u32 expkey[SERPENT_EXPKEY_WORDS];
};

DECLARE_CRYPTO_API(CONFIG_CRYPTO_SERPENT, __serpent_setkey, int,
	(struct serpent_ctx *ctx, const u8 *key, unsigned int keylen),
	(ctx, key, keylen));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_SERPENT, serpent_setkey, int,
	(struct crypto_tfm *tfm, const u8 *key, unsigned int keylen),
	(tfm, key, keylen));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_SERPENT, __serpent_encrypt, void,
	(const void *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_SERPENT, __serpent_decrypt, void,
	(const void *ctx, u8 *dst, const u8 *src),
	(ctx, dst, src));

#endif
