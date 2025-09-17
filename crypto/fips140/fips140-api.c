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

/*
 * crypto/ahash.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_HASH2)

#include <crypto/hash.h>
#include <crypto/internal/hash.h>

DEFINE_CRYPTO_API_STUB(crypto_hash_walk_first);
DEFINE_CRYPTO_API_STUB(crypto_hash_walk_done);
DEFINE_CRYPTO_API_STUB(shash_ahash_update);
DEFINE_CRYPTO_API_STUB(shash_ahash_finup);
DEFINE_CRYPTO_API_STUB(shash_ahash_digest);
DEFINE_CRYPTO_API_STUB(crypto_ahash_setkey);
DEFINE_CRYPTO_API_STUB(crypto_ahash_init);
DEFINE_CRYPTO_API_STUB(crypto_ahash_update);
DEFINE_CRYPTO_API_STUB(crypto_ahash_finup);
DEFINE_CRYPTO_API_STUB(crypto_ahash_digest);
DEFINE_CRYPTO_API_STUB(crypto_ahash_export_core);
DEFINE_CRYPTO_API_STUB(crypto_ahash_export);
DEFINE_CRYPTO_API_STUB(crypto_ahash_import_core);
DEFINE_CRYPTO_API_STUB(crypto_ahash_import);
DEFINE_CRYPTO_API_STUB(crypto_grab_ahash);
DEFINE_CRYPTO_API_STUB(crypto_alloc_ahash);
DEFINE_CRYPTO_API_STUB(crypto_has_ahash);
DEFINE_CRYPTO_API_STUB(crypto_hash_alg_has_setkey);
DEFINE_CRYPTO_API_STUB(crypto_clone_ahash);
DEFINE_CRYPTO_API_STUB(crypto_register_ahash);
DEFINE_CRYPTO_API_STUB(crypto_unregister_ahash);
DEFINE_CRYPTO_API_STUB(crypto_register_ahashes);
DEFINE_CRYPTO_API_STUB(crypto_unregister_ahashes);
DEFINE_CRYPTO_API_STUB(ahash_register_instance);
DEFINE_CRYPTO_API_STUB(ahash_request_free);
DEFINE_CRYPTO_API_STUB(crypto_hash_digest);
DEFINE_CRYPTO_API_STUB(ahash_free_singlespawn_instance);

/*
 * crypto/shash.c
 */

DEFINE_CRYPTO_API_STUB(shash_no_setkey);
DEFINE_CRYPTO_API_STUB(crypto_shash_setkey);
DEFINE_CRYPTO_API_STUB(crypto_shash_init);
DEFINE_CRYPTO_API_STUB(crypto_shash_finup);
DEFINE_CRYPTO_API_STUB(crypto_shash_digest);
DEFINE_CRYPTO_API_STUB(crypto_shash_tfm_digest);
DEFINE_CRYPTO_API_STUB(crypto_shash_export_core);
DEFINE_CRYPTO_API_STUB(crypto_shash_export);
DEFINE_CRYPTO_API_STUB(crypto_shash_import_core);
DEFINE_CRYPTO_API_STUB(crypto_shash_import);
DEFINE_CRYPTO_API_STUB(crypto_grab_shash);
DEFINE_CRYPTO_API_STUB(crypto_alloc_shash);
DEFINE_CRYPTO_API_STUB(crypto_has_shash);
DEFINE_CRYPTO_API_STUB(crypto_clone_shash);
DEFINE_CRYPTO_API_STUB(crypto_register_shash);
DEFINE_CRYPTO_API_STUB(crypto_unregister_shash);
DEFINE_CRYPTO_API_STUB(crypto_register_shashes);
DEFINE_CRYPTO_API_STUB(crypto_unregister_shashes);
DEFINE_CRYPTO_API_STUB(shash_register_instance);
DEFINE_CRYPTO_API_STUB(shash_free_singlespawn_instance);

#endif

/*
 * crypto/akcipher.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_AKCIPHER2)

#include <crypto/akcipher.h>
#include <crypto/internal/akcipher.h>

DEFINE_CRYPTO_API_STUB(crypto_grab_akcipher);
DEFINE_CRYPTO_API_STUB(crypto_alloc_akcipher);
DEFINE_CRYPTO_API_STUB(crypto_register_akcipher);
DEFINE_CRYPTO_API_STUB(crypto_unregister_akcipher);
DEFINE_CRYPTO_API_STUB(akcipher_register_instance);
DEFINE_CRYPTO_API_STUB(crypto_akcipher_sync_encrypt);
DEFINE_CRYPTO_API_STUB(crypto_akcipher_sync_decrypt);

#endif

/*
 * crypto/sig.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_SIG2)

#include <crypto/sig.h>
#include <crypto/internal/sig.h>

DEFINE_CRYPTO_API_STUB(crypto_alloc_sig);
DEFINE_CRYPTO_API_STUB(crypto_register_sig);
DEFINE_CRYPTO_API_STUB(crypto_unregister_sig);
DEFINE_CRYPTO_API_STUB(sig_register_instance);
DEFINE_CRYPTO_API_STUB(crypto_grab_sig);

#endif

/*
 * crypto/kpp.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_KPP2)

#include <crypto/kpp.h>
#include <crypto/internal/kpp.h>

DEFINE_CRYPTO_API_STUB(crypto_alloc_kpp);
DEFINE_CRYPTO_API_STUB(crypto_grab_kpp);
DEFINE_CRYPTO_API_STUB(crypto_has_kpp);
DEFINE_CRYPTO_API_STUB(crypto_register_kpp);
DEFINE_CRYPTO_API_STUB(crypto_unregister_kpp);
DEFINE_CRYPTO_API_STUB(kpp_register_instance);

#endif

/*
 * crypto/rsa_helper.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_RSA)

#include <crypto/internal/rsa.h>

DEFINE_CRYPTO_API_STUB(rsa_parse_pub_key);
DEFINE_CRYPTO_API_STUB(rsa_parse_priv_key);

#endif

/*
 * crypto/acompress.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_ACOMP2)

#include <crypto/acompress.h>
#include <crypto/internal/acompress.h>

DEFINE_CRYPTO_API_STUB(crypto_alloc_acomp);
DEFINE_CRYPTO_API_STUB(crypto_alloc_acomp_node);
DEFINE_CRYPTO_API_STUB(crypto_acomp_compress);
DEFINE_CRYPTO_API_STUB(crypto_acomp_decompress);
DEFINE_CRYPTO_API_STUB(crypto_register_acomp);
DEFINE_CRYPTO_API_STUB(crypto_unregister_acomp);
DEFINE_CRYPTO_API_STUB(crypto_register_acomps);
DEFINE_CRYPTO_API_STUB(crypto_unregister_acomps);
DEFINE_CRYPTO_API_STUB(crypto_acomp_free_streams);
DEFINE_CRYPTO_API_STUB(crypto_acomp_alloc_streams);
DEFINE_CRYPTO_API_STUB(crypto_acomp_lock_stream_bh);
DEFINE_CRYPTO_API_STUB(acomp_walk_done_src);
DEFINE_CRYPTO_API_STUB(acomp_walk_done_dst);
DEFINE_CRYPTO_API_STUB(acomp_walk_next_src);
DEFINE_CRYPTO_API_STUB(acomp_walk_next_dst);
DEFINE_CRYPTO_API_STUB(acomp_walk_virt);
DEFINE_CRYPTO_API_STUB(acomp_request_clone);

#endif

/*
 * crypto/scompress.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_ACOMP2)

#include <crypto/internal/scompress.h>

DEFINE_CRYPTO_API_STUB(crypto_register_scomp);
DEFINE_CRYPTO_API_STUB(crypto_unregister_scomp);
DEFINE_CRYPTO_API_STUB(crypto_register_scomps);
DEFINE_CRYPTO_API_STUB(crypto_unregister_scomps);

#endif