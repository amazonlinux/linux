/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AES-GCM authenticated encryption and decryption
 *
 * Copyright 2026 Google LLC
 *
 * Here this is upstream's one-shot AES-GCM interface on top of the certified
 * AES-GCM library, lib/crypto/aesgcm.c, whose interface is declared in the
 * frozen <crypto/gcm.h>.  Upstream (7.3) implements AES-GCM inside libaes and
 * computes GHASH with the gf128hash library, whose struct ghash_ctx collides
 * with the one in <crypto/ghash.h>, frozen inside the FIPS module boundary.
 * The function signatures below are upstream's, so callers keep upstream's
 * code; only struct aes_gcm_key differs, and it is private.
 *
 * Upstream's incremental interface (struct aes_gcm_ctx, aes_gcm_init() and
 * the update/final functions) has no counterpart in the certified library
 * and no user in this tree, so it is not declared: a new user fails to
 * compile rather than link against something that is not there.
 */
#ifndef _CRYPTO_AES_GCM_H
#define _CRYPTO_AES_GCM_H

#include <crypto/aes.h>
#include <crypto/gcm.h>
#include <linux/bug.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/types.h>

/**
 * struct aes_gcm_key - A key prepared for AES-GCM encryption and decryption
 */
struct aes_gcm_key {
	/* private: */
	/* AES key schedule, GHASH key and tag length of the certified library */
	struct aesgcm_ctx ctx;
};

/**
 * aes_gcm_preparekey() - Prepare a key for AES-GCM encryption and decryption
 * @key: (output) The key structure to initialize
 * @in_key: The raw AES-GCM key
 * @key_len: Length of the raw key in bytes: 16, 24, or 32
 * @authtag_len: Length of the authentication tag in bytes:
 *		 4, 8, 12, 13, 14, 15, or 16.  16 is recommended.
 *
 * Users should use memzero_explicit() to zeroize the key struct at the end of
 * its lifetime.  (But if this function fails, zeroization is unnecessary.)
 *
 * Context: Any context.
 * Return:
 * * 0 on success
 * * -EINVAL if either of the lengths is invalid
 */
static inline int __must_check aes_gcm_preparekey(struct aes_gcm_key *key,
						  const u8 *in_key,
						  size_t key_len,
						  size_t authtag_len)
{
	/* the certified library takes unsigned int lengths */
	if (key_len > UINT_MAX || authtag_len > UINT_MAX)
		return -EINVAL;
	return aesgcm_expandkey(&key->ctx, in_key, key_len, authtag_len);
}

/**
 * aes_gcm_encrypt() - Encrypt a message with AES-GCM
 * @dst: The destination ciphertext data.  Can be in-place or out-of-place.
 *	 For other overlaps the behavior is unspecified.
 * @src: The source plaintext data
 * @data_len: Length of plaintext in bytes (and ciphertext excluding the tag):
 *	      at most INT_MAX here (upstream: 2^36 - 32)
 * @authtag: The output authentication tag.  Length is the authtag_len that was
 *	     passed to aes_gcm_preparekey().  Usually protocols using AES-GCM
 *	     put the tag at the end of the ciphertext, in which case this should
 *	     be set to @dst + @data_len and @dst must have room for the tag.
 * @ad: The associated data
 * @ad_len: Length of associated data in bytes: at most INT_MAX here
 *	    (upstream: 2^61 - 1)
 * @nonce: The 12-byte nonce.  All (key, nonce) pairs used MUST be distinct.
 * @key: The key, already prepared using aes_gcm_preparekey()
 *
 * For AES-GMAC (i.e., AES-GCM without any data en/decrypted), use dst=NULL,
 * src=NULL, and data_len=0 to generate the AES-GMAC value.
 *
 * Context: Any context.
 */
static inline void aes_gcm_encrypt(u8 *dst, const u8 *src, size_t data_len,
				   u8 *authtag, const u8 *ad, size_t ad_len,
				   const u8 nonce[at_least 12],
				   const struct aes_gcm_key *key)
{
	/* the certified library takes int lengths */
	if (WARN_ON_ONCE(data_len > INT_MAX || ad_len > INT_MAX))
		return;
	aesgcm_encrypt(&key->ctx, dst, src, data_len, ad, ad_len, nonce,
		       authtag);
}

/**
 * aes_gcm_decrypt() - Decrypt a message with AES-GCM
 * @dst: The destination plaintext data.  Can be in-place or out-of-place.
 *	 For other overlaps the behavior is unspecified.
 * @src: The source ciphertext data
 * @data_len: Length of plaintext in bytes (and ciphertext excluding the tag):
 *	      at most INT_MAX here (upstream: 2^36 - 32)
 * @authtag: The stored authentication tag.  Length is the authtag_len that was
 *	     passed to aes_gcm_preparekey().  Usually protocols using AES-GCM
 *	     put the tag at the end of the ciphertext, in which case this should
 *	     be set to @src + @data_len and @src must have room for the tag.
 * @ad: The associated data
 * @ad_len: Length of associated data in bytes: at most INT_MAX here
 *	    (upstream: 2^61 - 1)
 * @nonce: The 12-byte nonce
 * @key: The key, already prepared using aes_gcm_preparekey()
 *
 * For AES-GMAC (i.e., AES-GCM without any data en/decrypted), use dst=NULL,
 * src=NULL, and data_len=0 to verify the AES-GMAC value.
 *
 * The certified library checks the tag before it decrypts, so @dst is not
 * written at all when the message is inauthentic.
 *
 * Context: Any context.
 * Return:
 * * 0 on success.  This is the only case where any decrypted or associated data
 *   can be used.
 * * -EBADMSG if the message is inauthentic
 */
static inline int __must_check aes_gcm_decrypt(u8 *dst, const u8 *src,
					       size_t data_len,
					       const u8 *authtag,
					       const u8 *ad, size_t ad_len,
					       const u8 nonce[at_least 12],
					       const struct aes_gcm_key *key)
{
	/* the certified library takes int lengths */
	if (WARN_ON_ONCE(data_len > INT_MAX || ad_len > INT_MAX))
		return -EBADMSG;
	if (!aesgcm_decrypt(&key->ctx, dst, src, data_len, ad, ad_len, nonce,
			    authtag))
		return -EBADMSG;
	return 0;
}

#endif /* _CRYPTO_AES_GCM_H */
