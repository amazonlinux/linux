/*
 * crypto/api.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO)

#include <linux/crypto.h>

DEFINE_CRYPTO_API_STUB(crypto_req_done);
DEFINE_CRYPTO_API_STUB(crypto_has_alg);
DEFINE_CRYPTO_API_STUB(crypto_alloc_base);
DEFINE_CRYPTO_API_STUB(crypto_destroy_tfm);
DEFINE_CRYPTO_API_STUB(crypto_request_clone);

#include <crypto/algapi.h>

DEFINE_CRYPTO_API_STUB(crypto_mod_put);

#include <crypto/internal.h>

DEFINE_CRYPTO_API_STUB(crypto_mod_get);
DEFINE_CRYPTO_API_STUB(crypto_alg_mod_lookup);
DEFINE_CRYPTO_API_STUB(crypto_larval_alloc);
DEFINE_CRYPTO_API_STUB(crypto_schedule_test);
DEFINE_CRYPTO_API_STUB(crypto_shoot_alg);
DEFINE_CRYPTO_API_STUB(__crypto_alloc_tfmgfp);
DEFINE_CRYPTO_API_STUB(__crypto_alloc_tfm);
DEFINE_CRYPTO_API_STUB(crypto_create_tfm_node);
DEFINE_CRYPTO_API_STUB(crypto_clone_tfm);
DEFINE_CRYPTO_API_STUB(crypto_find_alg);
DEFINE_CRYPTO_API_STUB(crypto_alloc_tfm_node);
DEFINE_CRYPTO_API_STUB(crypto_probing_notify);
DEFINE_CRYPTO_API_STUB(crypto_destroy_alg);

#endif
/*
 * crypto/cipher.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO)

#include <crypto/internal/cipher.h>

DEFINE_CRYPTO_API_STUB(crypto_cipher_setkey);
DEFINE_CRYPTO_API_STUB(crypto_cipher_encrypt_one);
DEFINE_CRYPTO_API_STUB(crypto_cipher_decrypt_one);
DEFINE_CRYPTO_API_STUB(crypto_clone_cipher);

#endif
/*
 * crypto/scatterwalk.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_ALGAPI2)

#include <crypto/scatterwalk.h>

DEFINE_CRYPTO_API_STUB(scatterwalk_skip);
DEFINE_CRYPTO_API_STUB(memcpy_from_scatterwalk);
DEFINE_CRYPTO_API_STUB(memcpy_to_scatterwalk);
DEFINE_CRYPTO_API_STUB(memcpy_from_sglist);
DEFINE_CRYPTO_API_STUB(memcpy_to_sglist);
DEFINE_CRYPTO_API_STUB(memcpy_sglist);
DEFINE_CRYPTO_API_STUB(scatterwalk_ffwd);
DEFINE_CRYPTO_API_STUB(skcipher_walk_first);
DEFINE_CRYPTO_API_STUB(skcipher_walk_done);

#endif
/*
 * crypto/algapi.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_ALGAPI2)

#include <crypto/algapi.h>

DEFINE_CRYPTO_API_STUB(crypto_register_alg);
DEFINE_CRYPTO_API_STUB(crypto_unregister_alg);
DEFINE_CRYPTO_API_STUB(crypto_register_algs);
DEFINE_CRYPTO_API_STUB(crypto_unregister_algs);
DEFINE_CRYPTO_API_STUB(crypto_register_template);
DEFINE_CRYPTO_API_STUB(crypto_register_templates);
DEFINE_CRYPTO_API_STUB(crypto_unregister_template);
DEFINE_CRYPTO_API_STUB(crypto_unregister_templates);
DEFINE_CRYPTO_API_STUB(crypto_lookup_template);
DEFINE_CRYPTO_API_STUB(crypto_register_instance);
DEFINE_CRYPTO_API_STUB(crypto_unregister_instance);
DEFINE_CRYPTO_API_STUB(crypto_grab_spawn);
DEFINE_CRYPTO_API_STUB(crypto_drop_spawn);
DEFINE_CRYPTO_API_STUB(crypto_spawn_tfm);
DEFINE_CRYPTO_API_STUB(crypto_spawn_tfm2);
DEFINE_CRYPTO_API_STUB(crypto_get_attr_type);
DEFINE_CRYPTO_API_STUB(crypto_check_attr_type);
DEFINE_CRYPTO_API_STUB(crypto_attr_alg_name);
DEFINE_CRYPTO_API_STUB(__crypto_inst_setname);
DEFINE_CRYPTO_API_STUB(crypto_init_queue);
DEFINE_CRYPTO_API_STUB(crypto_enqueue_request);
DEFINE_CRYPTO_API_STUB(crypto_enqueue_request_head);
DEFINE_CRYPTO_API_STUB(crypto_dequeue_request);
DEFINE_CRYPTO_API_STUB(crypto_inc);
DEFINE_CRYPTO_API_STUB(crypto_register_notifier);
DEFINE_CRYPTO_API_STUB(crypto_unregister_notifier);

#include <crypto/internal.h>

DEFINE_CRYPTO_API_STUB(crypto_alg_tested);
DEFINE_CRYPTO_API_STUB(crypto_remove_spawns);
DEFINE_CRYPTO_API_STUB(crypto_remove_final);
DEFINE_CRYPTO_API_STUB(crypto_alg_extsize);
DEFINE_CRYPTO_API_STUB(crypto_type_has_alg);

#endif

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