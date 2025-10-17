/* SPDX-License-Identifier: GPL-2.0 */

#include <crypto/api.h>
#include <crypto/aes.h>

DECLARE_CRYPTO_API(CONFIG_CRYPTO_AES_ARM64_CE, ce_aes_setkey, int,
	(struct crypto_tfm *tfm, const u8 *in_key, unsigned int key_len),
	(tfm, in_key, key_len));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_AES_ARM64_CE, ce_aes_expandkey, int,
	(struct crypto_aes_ctx *ctx, const u8 *in_key, unsigned int key_len),
	(ctx, in_key, key_len));
