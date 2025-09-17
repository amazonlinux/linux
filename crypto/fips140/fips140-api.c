// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Define static call keys for any functions which are part of the crypto
 * API and used by the standalone FIPS module but which are not built into
 * vmlinux.
 */

/*
 * crypto/aes_generic.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_AES)

#include <crypto/aes.h>

DEFINE_CRYPTO_API_STUB(crypto_aes_set_key);

#endif

/*
 * crypto/aead.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_AEAD2)

#include <crypto/aead.h>

DEFINE_CRYPTO_API_STUB(crypto_alloc_aead);
DEFINE_CRYPTO_API_STUB(crypto_has_aead);
DEFINE_CRYPTO_API_STUB(crypto_aead_setkey);
DEFINE_CRYPTO_API_STUB(crypto_aead_setauthsize);
DEFINE_CRYPTO_API_STUB(crypto_aead_encrypt);
DEFINE_CRYPTO_API_STUB(crypto_aead_decrypt);

#include <crypto/internal/aead.h>

DEFINE_CRYPTO_API_STUB(crypto_grab_aead);
DEFINE_CRYPTO_API_STUB(crypto_register_aead);
DEFINE_CRYPTO_API_STUB(crypto_unregister_aead);
DEFINE_CRYPTO_API_STUB(crypto_register_aeads);
DEFINE_CRYPTO_API_STUB(crypto_unregister_aeads);
DEFINE_CRYPTO_API_STUB(aead_register_instance);

#endif

/*
 * crypto/geniv.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_GENIV)

#include <crypto/internal/geniv.h>

DEFINE_CRYPTO_API_STUB(aead_geniv_alloc);
DEFINE_CRYPTO_API_STUB(aead_init_geniv);
DEFINE_CRYPTO_API_STUB(aead_exit_geniv);

#endif

/*
 * crypto/lskcipher.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_SKCIPHER2)

#include <crypto/skcipher.h>

DEFINE_CRYPTO_API_STUB(crypto_alloc_lskcipher);
DEFINE_CRYPTO_API_STUB(crypto_lskcipher_setkey);
DEFINE_CRYPTO_API_STUB(crypto_lskcipher_encrypt);
DEFINE_CRYPTO_API_STUB(crypto_lskcipher_decrypt);

#include <crypto/internal/skcipher.h>

DEFINE_CRYPTO_API_STUB(crypto_grab_lskcipher);
DEFINE_CRYPTO_API_STUB(crypto_register_lskcipher);
DEFINE_CRYPTO_API_STUB(crypto_unregister_lskcipher);
DEFINE_CRYPTO_API_STUB(crypto_register_lskciphers);
DEFINE_CRYPTO_API_STUB(crypto_unregister_lskciphers);
DEFINE_CRYPTO_API_STUB(lskcipher_register_instance);
DEFINE_CRYPTO_API_STUB(lskcipher_alloc_instance_simple);

/*
 * crypto/skcipher.c
 */
DEFINE_CRYPTO_API_STUB(crypto_alloc_skcipher);
DEFINE_CRYPTO_API_STUB(crypto_alloc_sync_skcipher);
DEFINE_CRYPTO_API_STUB(crypto_has_skcipher);
DEFINE_CRYPTO_API_STUB(crypto_skcipher_setkey);
DEFINE_CRYPTO_API_STUB(crypto_skcipher_encrypt);
DEFINE_CRYPTO_API_STUB(crypto_skcipher_decrypt);
DEFINE_CRYPTO_API_STUB(crypto_skcipher_export);
DEFINE_CRYPTO_API_STUB(crypto_skcipher_import);
DEFINE_CRYPTO_API_STUB(crypto_grab_skcipher);
DEFINE_CRYPTO_API_STUB(crypto_register_skcipher);
DEFINE_CRYPTO_API_STUB(crypto_unregister_skcipher);
DEFINE_CRYPTO_API_STUB(crypto_register_skciphers);
DEFINE_CRYPTO_API_STUB(crypto_unregister_skciphers);
DEFINE_CRYPTO_API_STUB(skcipher_register_instance);
DEFINE_CRYPTO_API_STUB(skcipher_walk_virt);
DEFINE_CRYPTO_API_STUB(skcipher_walk_aead_encrypt);
DEFINE_CRYPTO_API_STUB(skcipher_walk_aead_decrypt);
DEFINE_CRYPTO_API_STUB(skcipher_alloc_instance_simple);

#endif