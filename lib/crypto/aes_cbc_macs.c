// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * AES-CMAC, AES-XCBC-MAC and AES-CBC-MAC library functions.
 *
 * This code is upstream's, extracted verbatim from lib/crypto/aes.c (7.1; the
 * functions are unchanged in 7.3).  It lives in its own file here because
 * lib/crypto/aes.c carries the certified single-block AES implementation, which
 * predates these functions.  The only change is the removal of the
 * aes_cbcmac_blocks_arch() hook, whose x86 and arm64 backends are gone:
 * accelerated AES is inside the certified FIPS module, and upstream's own
 * fallback for that hook is the generic loop below.  Upstream's AES-CMAC FIPS
 * self-test (7.3) is not carried: it is part of the library self-tests in
 * lib/crypto/fips-aes.h, which went away with upstream's lib/crypto/aes.c.
 *
 * The AES key object is struct crypto_aes_ctx here (see <crypto/aes_wrapper.h>),
 * so aes_encrypt() and aes_prepareenckey() resolve to the certified
 * implementation in lib/crypto/aes.c.
 */

#include <crypto/aes-cbc-macs.h>
#include <crypto/aes.h>
#include <crypto/aes_wrapper.h>
#include <crypto/utils.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/string.h>

#if IS_ENABLED(CONFIG_CRYPTO_LIB_AES_CBC_MACS)

static void aes_cbcmac_blocks(u8 h[AES_BLOCK_SIZE],
			      const struct aes_enckey *key, const u8 *data,
			      size_t nblocks, bool enc_before, bool enc_after)
{
	if (enc_before)
		aes_encrypt(key, h, h);
	for (; nblocks > 1; nblocks--) {
		crypto_xor(h, data, AES_BLOCK_SIZE);
		data += AES_BLOCK_SIZE;
		aes_encrypt(key, h, h);
	}
	crypto_xor(h, data, AES_BLOCK_SIZE);
	if (enc_after)
		aes_encrypt(key, h, h);
}

int aes_cmac_preparekey(struct aes_cmac_key *key, const u8 *in_key,
			size_t key_len)
{
	u64 hi, lo, mask;
	int err;

	/* Prepare the AES key. */
	err = aes_prepareenckey(&key->aes, in_key, key_len);
	if (err)
		return err;

	/*
	 * Prepare the subkeys K1 and K2 by encrypting the all-zeroes block,
	 * then multiplying by 'x' and 'x^2' (respectively) in GF(2^128).
	 * Reference: NIST SP 800-38B, Section 6.1 "Subkey Generation".
	 */
	memset(key->k_final[0].b, 0, AES_BLOCK_SIZE);
	aes_encrypt(&key->aes, key->k_final[0].b, key->k_final[0].b);
	hi = be64_to_cpu(key->k_final[0].w[0]);
	lo = be64_to_cpu(key->k_final[0].w[1]);
	for (int i = 0; i < 2; i++) {
		mask = ((s64)hi >> 63) & 0x87;
		hi = (hi << 1) ^ (lo >> 63);
		lo = (lo << 1) ^ mask;
		key->k_final[i].w[0] = cpu_to_be64(hi);
		key->k_final[i].w[1] = cpu_to_be64(lo);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(aes_cmac_preparekey);

void aes_xcbcmac_preparekey(struct aes_cmac_key *key,
			    const u8 in_key[AES_KEYSIZE_128])
{
	static const u8 constants[3][AES_BLOCK_SIZE] = {
		{ [0 ... AES_BLOCK_SIZE - 1] = 0x1 },
		{ [0 ... AES_BLOCK_SIZE - 1] = 0x2 },
		{ [0 ... AES_BLOCK_SIZE - 1] = 0x3 },
	};
	u8 new_aes_key[AES_BLOCK_SIZE];

	static_assert(AES_BLOCK_SIZE == AES_KEYSIZE_128);
	aes_prepareenckey(&key->aes, in_key, AES_BLOCK_SIZE);
	aes_encrypt(&key->aes, new_aes_key, constants[0]);
	aes_encrypt(&key->aes, key->k_final[0].b, constants[1]);
	aes_encrypt(&key->aes, key->k_final[1].b, constants[2]);
	aes_prepareenckey(&key->aes, new_aes_key, AES_BLOCK_SIZE);
	memzero_explicit(new_aes_key, AES_BLOCK_SIZE);
}
EXPORT_SYMBOL_GPL(aes_xcbcmac_preparekey);

void aes_cmac_update(struct aes_cmac_ctx *ctx, const u8 *data, size_t data_len)
{
	bool enc_before = false;
	size_t nblocks;

	if (ctx->partial_len) {
		/* XOR data into a pending block. */
		size_t l = min(data_len, AES_BLOCK_SIZE - ctx->partial_len);

		crypto_xor(&ctx->h[ctx->partial_len], data, l);
		data += l;
		data_len -= l;
		ctx->partial_len += l;
		if (data_len == 0) {
			/*
			 * Either the pending block hasn't been filled yet, or
			 * no more data was given so it's not yet known whether
			 * the block is the final block.
			 */
			return;
		}
		/* Pending block has been filled and isn't the final block. */
		enc_before = true;
	}

	nblocks = data_len / AES_BLOCK_SIZE;
	data_len %= AES_BLOCK_SIZE;
	if (nblocks == 0) {
		/* 0 additional full blocks, then optionally a partial block */
		if (enc_before)
			aes_encrypt(&ctx->key->aes, ctx->h, ctx->h);
		crypto_xor(ctx->h, data, data_len);
		ctx->partial_len = data_len;
	} else if (data_len != 0) {
		/* 1 or more additional full blocks, then a partial block */
		aes_cbcmac_blocks(ctx->h, &ctx->key->aes, data, nblocks,
				  enc_before, /* enc_after= */ true);
		data += nblocks * AES_BLOCK_SIZE;
		crypto_xor(ctx->h, data, data_len);
		ctx->partial_len = data_len;
	} else {
		/*
		 * 1 or more additional full blocks only.  Encryption of the
		 * last block is delayed until it's known whether it's the final
		 * block in the message or not.
		 */
		aes_cbcmac_blocks(ctx->h, &ctx->key->aes, data, nblocks,
				  enc_before, /* enc_after= */ false);
		ctx->partial_len = AES_BLOCK_SIZE;
	}
}
EXPORT_SYMBOL_GPL(aes_cmac_update);

void aes_cmac_final(struct aes_cmac_ctx *ctx, u8 out[AES_BLOCK_SIZE])
{
	if (ctx->partial_len == AES_BLOCK_SIZE) {
		/* Final block is a full block.  Use k_final[0]. */
		crypto_xor(ctx->h, ctx->key->k_final[0].b, AES_BLOCK_SIZE);
	} else {
		/* Final block is a partial block.  Pad, and use k_final[1]. */
		ctx->h[ctx->partial_len] ^= 0x80;
		crypto_xor(ctx->h, ctx->key->k_final[1].b, AES_BLOCK_SIZE);
	}
	aes_encrypt(&ctx->key->aes, out, ctx->h);
	memzero_explicit(ctx, sizeof(*ctx));
}
EXPORT_SYMBOL_GPL(aes_cmac_final);

void aes_cbcmac_update(struct aes_cbcmac_ctx *ctx, const u8 *data,
		       size_t data_len)
{
	bool enc_before = false;
	size_t nblocks;

	if (ctx->partial_len) {
		size_t l = min(data_len, AES_BLOCK_SIZE - ctx->partial_len);

		crypto_xor(&ctx->h[ctx->partial_len], data, l);
		data += l;
		data_len -= l;
		ctx->partial_len += l;
		if (ctx->partial_len < AES_BLOCK_SIZE)
			return;
		enc_before = true;
	}

	nblocks = data_len / AES_BLOCK_SIZE;
	data_len %= AES_BLOCK_SIZE;
	if (nblocks == 0) {
		if (enc_before)
			aes_encrypt(ctx->key, ctx->h, ctx->h);
	} else {
		aes_cbcmac_blocks(ctx->h, ctx->key, data, nblocks, enc_before,
				  /* enc_after= */ true);
		data += nblocks * AES_BLOCK_SIZE;
	}
	crypto_xor(ctx->h, data, data_len);
	ctx->partial_len = data_len;
}
EXPORT_SYMBOL_NS_GPL(aes_cbcmac_update, "CRYPTO_INTERNAL");

void aes_cbcmac_final(struct aes_cbcmac_ctx *ctx, u8 out[AES_BLOCK_SIZE])
{
	if (ctx->partial_len)
		aes_encrypt(ctx->key, out, ctx->h);
	else
		memcpy(out, ctx->h, AES_BLOCK_SIZE);
	memzero_explicit(ctx, sizeof(*ctx));
}
EXPORT_SYMBOL_NS_GPL(aes_cbcmac_final, "CRYPTO_INTERNAL");

#endif /* CONFIG_CRYPTO_LIB_AES_CBC_MACS */
