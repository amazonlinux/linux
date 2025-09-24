/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HKDF: HMAC-based Key Derivation Function (HKDF), RFC 5869
 *
 * Extracted from fs/crypto/hkdf.c, which has
 * Copyright 2019 Google LLC
 */

#ifndef _CRYPTO_HKDF_H
#define _CRYPTO_HKDF_H

#include <crypto/api.h>
#include <crypto/hash.h>

DECLARE_CRYPTO_API(CONFIG_CRYPTO_HKDF, hkdf_extract, int,
	(struct crypto_shash *hmac_tfm, const u8 *ikm, unsigned int ikmlen, const u8 *salt, unsigned int saltlen, u8 *prk),
	(hmac_tfm, ikm, ikmlen, salt, saltlen, prk));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_HKDF, hkdf_expand, int,
	(struct crypto_shash *hmac_tfm, const u8 *info, unsigned int infolen, u8 *okm, unsigned int okmlen),
	(hmac_tfm, info, infolen, okm, okmlen));
#endif
