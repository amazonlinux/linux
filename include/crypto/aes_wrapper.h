/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Bridge between 7.1's AES key-object interface and the certified AES library.
 *
 * The certified sources have no encryption-only key object: they use
 * struct crypto_aes_ctx everywhere, and <crypto/aes.h> -- which is frozen
 * inside the FIPS boundary and so cannot carry these definitions -- declares
 * aes_encrypt() and aes_decrypt() in terms of it.  7.1 added
 * struct aes_enckey together with aes_prepareenckey(), and both went away when
 * lib/crypto/aes.c was restored to the certified version.
 *
 * struct aes_enckey is therefore aliased to struct crypto_aes_ctx rather than
 * wrapped in one.  The alias is what lets code written against 7.1's interface
 * compile unchanged: 'struct aes_enckey k' really is a crypto_aes_ctx, so
 * aes_encrypt(&k, ...) matches the certified prototype.  A wrapper struct would
 * force every such call to be renamed, because C has no overloading and, under
 * the kernel's -fms-extensions, no implicit conversion from a pointer to the
 * outer struct to a pointer to its first member.
 *
 * Include this header wherever struct aes_enckey or aes_prepareenckey() is used.
 */
#ifndef _CRYPTO_AES_WRAPPER_H
#define _CRYPTO_AES_WRAPPER_H

#include <crypto/aes.h>
#include <linux/types.h>

#define aes_enckey crypto_aes_ctx

/*
 * aes_expandkey() also computes the decryption round keys, which an
 * encryption-only caller does not need; that is one extra key schedule per key
 * setup.  Both functions return 0, or -EINVAL for an invalid key length, so the
 * error contract is unchanged.  7.1 typed key_len as size_t and the certified
 * prototype uses unsigned int; the value is 16, 24 or 32, so the conversion is
 * safe.
 */
static inline int aes_prepareenckey(struct aes_enckey *key, const u8 *in_key,
				    size_t key_len)
{
	return aes_expandkey(key, in_key, key_len);
}

#endif /* _CRYPTO_AES_WRAPPER_H */
