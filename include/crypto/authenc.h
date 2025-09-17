/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Authenc: Simple AEAD wrapper for IPsec
 *
 * Copyright (c) 2007 Herbert Xu <herbert@gondor.apana.org.au>
 */
#ifndef _CRYPTO_AUTHENC_H
#define _CRYPTO_AUTHENC_H

#include <crypto/api.h>
#include <linux/types.h>

enum {
	CRYPTO_AUTHENC_KEYA_UNSPEC,
	CRYPTO_AUTHENC_KEYA_PARAM,
};

struct crypto_authenc_key_param {
	__be32 enckeylen;
};

struct crypto_authenc_keys {
	const u8 *authkey;
	const u8 *enckey;

	unsigned int authkeylen;
	unsigned int enckeylen;
};

DECLARE_CRYPTO_API(CONFIG_CRYPTO_AUTHENC, crypto_authenc_extractkeys, int,
	(struct crypto_authenc_keys *keys, const u8 *key, unsigned int keylen),
	(keys, key, keylen));
int crypto_krb5enc_extractkeys(struct crypto_authenc_keys *keys, const u8 *key,
			       unsigned int keylen);

#endif	/* _CRYPTO_AUTHENC_H */
