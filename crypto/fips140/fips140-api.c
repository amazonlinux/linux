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

/*
 * crypto/testmgr.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_MANAGER2)

#include <crypto/internal.h>

DEFINE_CRYPTO_API_STUB(alg_test);

#endif

/*
 * crypto/md5.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_MD5)

#include <crypto/md5.h>

#undef md5_zero_message_hash
DEFINE_CRYPTO_VAR_STUB(md5_zero_message_hash);

#endif

/*
 * crypto/sha3_generic.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_SHA3)

#include <crypto/sha3.h>

#undef crypto_sha3_init
DEFINE_CRYPTO_API_STUB(crypto_sha3_init);

#endif

/*
 * crypto/authenc.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_AUTHENC)

#include <crypto/authenc.h>

DEFINE_CRYPTO_API_STUB(crypto_authenc_extractkeys);

#endif
/*
 * crypto/rng.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_RNG2)

#include <crypto/rng.h>

DEFINE_CRYPTO_API_STUB(crypto_get_default_rng);
DEFINE_CRYPTO_API_STUB(crypto_put_default_rng);
DEFINE_CRYPTO_API_STUB(crypto_alloc_rng);
DEFINE_CRYPTO_API_STUB(crypto_rng_reset);

#include <crypto/internal/rng.h>

DEFINE_CRYPTO_API_STUB(crypto_register_rng);
DEFINE_CRYPTO_API_STUB(crypto_unregister_rng);
DEFINE_CRYPTO_API_STUB(crypto_register_rngs);
DEFINE_CRYPTO_API_STUB(crypto_unregister_rngs);
DEFINE_CRYPTO_API_STUB(crypto_del_default_rng);

#endif
/*
 * crypto/asymmetric_keys/asymmetric_type.c
 */
#if IS_BUILTIN(CONFIG_ASYMMETRIC_KEY_TYPE)

#include <keys/asymmetric-parser.h>

DEFINE_CRYPTO_API_STUB(register_asymmetric_key_parser);
DEFINE_CRYPTO_API_STUB(unregister_asymmetric_key_parser);

#include <keys/asymmetric-type.h>

DEFINE_CRYPTO_API_STUB(asymmetric_key_id_same);
DEFINE_CRYPTO_API_STUB(asymmetric_key_id_partial);
DEFINE_CRYPTO_API_STUB(asymmetric_key_generate_id);
DEFINE_CRYPTO_API_STUB(find_asymmetric_key);

#undef key_type_asymmetric
DEFINE_CRYPTO_VAR_STUB(key_type_asymmetric);

#endif
/*
 * crypto/asymmetric_keys/signature.c
 */
#if IS_BUILTIN(CONFIG_ASYMMETRIC_KEY_TYPE)

#include <crypto/public_key.h>

DEFINE_CRYPTO_API_STUB(public_key_signature_free);
DEFINE_CRYPTO_API_STUB(query_asymmetric_key);
DEFINE_CRYPTO_API_STUB(verify_signature);

#endif
/*
 * crypto/asymmetric_keys/restrict.c
 */
#if IS_BUILTIN(CONFIG_ASYMMETRIC_KEY_TYPE)

#include <crypto/public_key.h>

DEFINE_CRYPTO_API_STUB(restrict_link_by_signature);
DEFINE_CRYPTO_API_STUB(restrict_link_by_digsig);

#endif
/*
 * crypto/asymmetric_keys/public_key.c
 */
#if IS_BUILTIN(CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE)

#include <crypto/public_key.h>

DEFINE_CRYPTO_API_STUB(public_key_free);
DEFINE_CRYPTO_API_STUB(public_key_verify_signature);

#undef public_key_subtype
DEFINE_CRYPTO_VAR_STUB(public_key_subtype);

#endif
/*
 * crypto/asymmetric_keys/x509_cert_parser.c
 */
#if IS_BUILTIN(CONFIG_X509_CERTIFICATE_PARSER)

#include <crypto/asymmetric_keys/x509_parser.h>

DEFINE_CRYPTO_API_STUB(x509_free_certificate);
DEFINE_CRYPTO_API_STUB(x509_cert_parse);
DEFINE_CRYPTO_API_STUB(x509_decode_time);

#endif
/*
 * crypto/asymmetric_keys/x509_loader.c
 */
#if IS_BUILTIN(CONFIG_X509_CERTIFICATE_PARSER)

#include <keys/asymmetric-type.h>

DEFINE_CRYPTO_API_STUB(x509_load_certificate_list);

#endif
/*
 * crypto/asymmetric_keys/pkcs7_parser.c
 */
#if IS_BUILTIN(CONFIG_PKCS7_MESSAGE_PARSER)

#include <crypto/pkcs7.h>

DEFINE_CRYPTO_API_STUB(pkcs7_parse_message);
DEFINE_CRYPTO_API_STUB(pkcs7_free_message);
DEFINE_CRYPTO_API_STUB(pkcs7_get_content_data);

#endif
/*
 * crypto/asymmetric_keys/pkcs7_trust.c
 */
#if IS_BUILTIN(CONFIG_PKCS7_MESSAGE_PARSER)

#include <crypto/pkcs7.h>

DEFINE_CRYPTO_API_STUB(pkcs7_validate_trust);

#endif
/*
 * crypto/asymmetric_keys/pkcs7_verify.c
 */
#if IS_BUILTIN(CONFIG_PKCS7_MESSAGE_PARSER)

#include <crypto/pkcs7.h>

DEFINE_CRYPTO_API_STUB(pkcs7_verify);
DEFINE_CRYPTO_API_STUB(pkcs7_supply_detached_data);

#endif
/*
 * crypto/crypto_engine.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_ENGINE)

#include <crypto/engine.h>

DEFINE_CRYPTO_API_STUB(crypto_transfer_aead_request_to_engine);
DEFINE_CRYPTO_API_STUB(crypto_transfer_akcipher_request_to_engine);
DEFINE_CRYPTO_API_STUB(crypto_transfer_hash_request_to_engine);
DEFINE_CRYPTO_API_STUB(crypto_transfer_kpp_request_to_engine);
DEFINE_CRYPTO_API_STUB(crypto_transfer_skcipher_request_to_engine);
DEFINE_CRYPTO_API_STUB(crypto_finalize_aead_request);
DEFINE_CRYPTO_API_STUB(crypto_finalize_akcipher_request);
DEFINE_CRYPTO_API_STUB(crypto_finalize_hash_request);
DEFINE_CRYPTO_API_STUB(crypto_finalize_kpp_request);
DEFINE_CRYPTO_API_STUB(crypto_finalize_skcipher_request);
DEFINE_CRYPTO_API_STUB(crypto_engine_start);
DEFINE_CRYPTO_API_STUB(crypto_engine_stop);
DEFINE_CRYPTO_API_STUB(crypto_engine_alloc_init);
DEFINE_CRYPTO_API_STUB(crypto_engine_alloc_init_and_set);
DEFINE_CRYPTO_API_STUB(crypto_engine_exit);
DEFINE_CRYPTO_API_STUB(crypto_engine_register_aead);
DEFINE_CRYPTO_API_STUB(crypto_engine_unregister_aead);
DEFINE_CRYPTO_API_STUB(crypto_engine_register_aeads);
DEFINE_CRYPTO_API_STUB(crypto_engine_unregister_aeads);
DEFINE_CRYPTO_API_STUB(crypto_engine_register_ahash);
DEFINE_CRYPTO_API_STUB(crypto_engine_unregister_ahash);
DEFINE_CRYPTO_API_STUB(crypto_engine_register_ahashes);
DEFINE_CRYPTO_API_STUB(crypto_engine_unregister_ahashes);
DEFINE_CRYPTO_API_STUB(crypto_engine_register_akcipher);
DEFINE_CRYPTO_API_STUB(crypto_engine_unregister_akcipher);
DEFINE_CRYPTO_API_STUB(crypto_engine_register_kpp);
DEFINE_CRYPTO_API_STUB(crypto_engine_unregister_kpp);
DEFINE_CRYPTO_API_STUB(crypto_engine_register_skcipher);
DEFINE_CRYPTO_API_STUB(crypto_engine_unregister_skcipher);
DEFINE_CRYPTO_API_STUB(crypto_engine_register_skciphers);
DEFINE_CRYPTO_API_STUB(crypto_engine_unregister_skciphers);

#endif
/*
 * crypto/hkdf.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_HKDF)

#include <crypto/hkdf.h>

DEFINE_CRYPTO_API_STUB(hkdf_extract);
DEFINE_CRYPTO_API_STUB(hkdf_expand);

#endif
/*
 * crypto/dh_helper.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_DH)

#include <crypto/dh.h>

DEFINE_CRYPTO_API_STUB(crypto_dh_key_len);
DEFINE_CRYPTO_API_STUB(crypto_dh_encode_key);
DEFINE_CRYPTO_API_STUB(crypto_dh_decode_key);

#endif
/*
 * crypto/ecc.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_ECC)

#include <crypto/ecc_curve.h>

DEFINE_CRYPTO_API_STUB(ecc_get_curve);
DEFINE_CRYPTO_API_STUB(ecc_get_curve25519);

#include <crypto/internal/ecc.h>

DEFINE_CRYPTO_API_STUB(ecc_digits_from_bytes);
DEFINE_CRYPTO_API_STUB(ecc_is_key_valid);
DEFINE_CRYPTO_API_STUB(ecc_gen_privkey);
DEFINE_CRYPTO_API_STUB(ecc_make_pub_key);
DEFINE_CRYPTO_API_STUB(crypto_ecdh_shared_secret);
DEFINE_CRYPTO_API_STUB(ecc_is_pubkey_valid_partial);
DEFINE_CRYPTO_API_STUB(ecc_is_pubkey_valid_full);
DEFINE_CRYPTO_API_STUB(vli_is_zero);
DEFINE_CRYPTO_API_STUB(vli_cmp);
DEFINE_CRYPTO_API_STUB(vli_sub);
DEFINE_CRYPTO_API_STUB(vli_from_be64);
DEFINE_CRYPTO_API_STUB(vli_from_le64);
DEFINE_CRYPTO_API_STUB(vli_mod_inv);
DEFINE_CRYPTO_API_STUB(vli_mod_mult_slow);
DEFINE_CRYPTO_API_STUB(vli_num_bits);
DEFINE_CRYPTO_API_STUB(ecc_alloc_point);
DEFINE_CRYPTO_API_STUB(ecc_free_point);
DEFINE_CRYPTO_API_STUB(ecc_point_is_zero);
DEFINE_CRYPTO_API_STUB(ecc_point_mult_shamir);

#endif
/*
 * crypto/nhpoly1305.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_NHPOLY1305)

#include <crypto/nhpoly1305.h>

DEFINE_CRYPTO_API_STUB(crypto_nhpoly1305_setkey);
DEFINE_CRYPTO_API_STUB(crypto_nhpoly1305_init);
DEFINE_CRYPTO_API_STUB(crypto_nhpoly1305_update);
DEFINE_CRYPTO_API_STUB(crypto_nhpoly1305_update_helper);
DEFINE_CRYPTO_API_STUB(crypto_nhpoly1305_final);
DEFINE_CRYPTO_API_STUB(crypto_nhpoly1305_final_helper);

#endif
/*
 * crypto/cryptd.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_CRYPTD)

#include <crypto/cryptd.h>

DEFINE_CRYPTO_API_STUB(cryptd_alloc_skcipher);
DEFINE_CRYPTO_API_STUB(cryptd_skcipher_child);
DEFINE_CRYPTO_API_STUB(cryptd_skcipher_queued);
DEFINE_CRYPTO_API_STUB(cryptd_free_skcipher);
DEFINE_CRYPTO_API_STUB(cryptd_alloc_ahash);
DEFINE_CRYPTO_API_STUB(cryptd_ahash_child);
DEFINE_CRYPTO_API_STUB(cryptd_shash_desc);
DEFINE_CRYPTO_API_STUB(cryptd_ahash_queued);
DEFINE_CRYPTO_API_STUB(cryptd_free_ahash);
DEFINE_CRYPTO_API_STUB(cryptd_alloc_aead);
DEFINE_CRYPTO_API_STUB(cryptd_aead_child);
DEFINE_CRYPTO_API_STUB(cryptd_aead_queued);
DEFINE_CRYPTO_API_STUB(cryptd_free_aead);

#endif
/*
 * crypto/blowfish_common.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_BLOWFISH_COMMON)

#include <crypto/blowfish.h>

DEFINE_CRYPTO_API_STUB(blowfish_setkey);

#endif
/*
 * crypto/sm4.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_SM4)

#include <crypto/sm4.h>

#undef crypto_sm4_fk
#undef crypto_sm4_ck
#undef crypto_sm4_sbox
DEFINE_CRYPTO_VAR_STUB(crypto_sm4_fk);
DEFINE_CRYPTO_VAR_STUB(crypto_sm4_ck);
DEFINE_CRYPTO_VAR_STUB(crypto_sm4_sbox);

DEFINE_CRYPTO_API_STUB(sm4_expandkey);
DEFINE_CRYPTO_API_STUB(sm4_crypt_block);

#endif
/*
 * crypto/twofish_common.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_TWOFISH_COMMON)

#include <crypto/twofish.h>

DEFINE_CRYPTO_API_STUB(__twofish_setkey);
DEFINE_CRYPTO_API_STUB(twofish_setkey);

#endif
/*
 * crypto/serpent_generic.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_SERPENT)

#include <crypto/serpent.h>

DEFINE_CRYPTO_API_STUB(__serpent_setkey);
DEFINE_CRYPTO_API_STUB(serpent_setkey);
DEFINE_CRYPTO_API_STUB(__serpent_encrypt);
DEFINE_CRYPTO_API_STUB(__serpent_decrypt);

#endif
/*
 * crypto/cast_common.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_CAST_COMMON)

#include <crypto/cast_common.h>

#undef cast_s1
#undef cast_s2
#undef cast_s3
#undef cast_s4
DEFINE_CRYPTO_VAR_STUB(cast_s1);
DEFINE_CRYPTO_VAR_STUB(cast_s2);
DEFINE_CRYPTO_VAR_STUB(cast_s3);
DEFINE_CRYPTO_VAR_STUB(cast_s4);

#endif
/*
 * crypto/cast5_generic.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_CAST5)

#include <crypto/cast5.h>

DEFINE_CRYPTO_API_STUB(cast5_setkey);
DEFINE_CRYPTO_API_STUB(__cast5_encrypt);
DEFINE_CRYPTO_API_STUB(__cast5_decrypt);

#endif
/*
 * crypto/cast6_generic.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_CAST6)

#include <crypto/cast6.h>

DEFINE_CRYPTO_API_STUB(__cast6_setkey);
DEFINE_CRYPTO_API_STUB(cast6_setkey);
DEFINE_CRYPTO_API_STUB(__cast6_encrypt);
DEFINE_CRYPTO_API_STUB(__cast6_decrypt);

#endif
/*
 * crypto/af_alg.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_USER_API)

#include <crypto/if_alg.h>

DEFINE_CRYPTO_API_STUB(af_alg_register_type);
DEFINE_CRYPTO_API_STUB(af_alg_unregister_type);
DEFINE_CRYPTO_API_STUB(af_alg_release);
DEFINE_CRYPTO_API_STUB(af_alg_release_parent);
DEFINE_CRYPTO_API_STUB(af_alg_accept);
DEFINE_CRYPTO_API_STUB(af_alg_free_sg);
DEFINE_CRYPTO_API_STUB(af_alg_count_tsgl);
DEFINE_CRYPTO_API_STUB(af_alg_pull_tsgl);
DEFINE_CRYPTO_API_STUB(af_alg_wmem_wakeup);
DEFINE_CRYPTO_API_STUB(af_alg_wait_for_data);
DEFINE_CRYPTO_API_STUB(af_alg_sendmsg);
DEFINE_CRYPTO_API_STUB(af_alg_free_resources);
DEFINE_CRYPTO_API_STUB(af_alg_async_cb);
DEFINE_CRYPTO_API_STUB(af_alg_poll);
DEFINE_CRYPTO_API_STUB(af_alg_alloc_areq);
DEFINE_CRYPTO_API_STUB(af_alg_get_rsgl);

#endif
/*
 * crypto/aria_generic.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_ARIA)

#include <crypto/aria.h>

DEFINE_CRYPTO_API_STUB(aria_set_key);
DEFINE_CRYPTO_API_STUB(aria_encrypt);
DEFINE_CRYPTO_API_STUB(aria_decrypt);

#endif
/*
 * crypto/krb5enc.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_KRB5ENC)

#include <crypto/authenc.h>

DEFINE_CRYPTO_API_STUB(crypto_krb5enc_extractkeys);

#endif
/*
 * crypto/xor.c
 */
#if IS_BUILTIN(CONFIG_XOR_BLOCKS)

#include <linux/raid/xor.h>

DEFINE_CRYPTO_API_STUB(xor_blocks);

#endif
/*
 * crypto/async_tx/async_tx.c
 */
#if IS_BUILTIN(CONFIG_ASYNC_CORE)

#include <linux/async_tx.h>

#ifdef CONFIG_DMA_ENGINE
DEFINE_CRYPTO_API_STUB(__async_tx_find_channel);
#endif
DEFINE_CRYPTO_API_STUB(async_tx_submit);
DEFINE_CRYPTO_API_STUB(async_trigger_callback);
DEFINE_CRYPTO_API_STUB(async_tx_quiesce);

#endif
/*
 * crypto/async_tx/async_memcpy.c
 */
#if IS_BUILTIN(CONFIG_ASYNC_MEMCPY)

#include <linux/async_tx.h>

DEFINE_CRYPTO_API_STUB(async_memcpy);

#endif
/*
 * crypto/async_tx/async_xor.c
 */
#if IS_BUILTIN(CONFIG_ASYNC_XOR)

#include <linux/async_tx.h>

DEFINE_CRYPTO_API_STUB(async_xor);
DEFINE_CRYPTO_API_STUB(async_xor_offs);
DEFINE_CRYPTO_API_STUB(async_xor_val_offs);

#endif
/*
 * crypto/async_tx/async_pq.c
 */
#if IS_BUILTIN(CONFIG_ASYNC_PQ)

#include <linux/async_tx.h>

DEFINE_CRYPTO_API_STUB(async_gen_syndrome);
DEFINE_CRYPTO_API_STUB(async_syndrome_val);

#endif
/*
 * crypto/async_tx/async_raid6_recov.c
 */
#if IS_BUILTIN(CONFIG_ASYNC_RAID6_RECOV)

#include <linux/async_tx.h>

DEFINE_CRYPTO_API_STUB(async_raid6_2data_recov);
DEFINE_CRYPTO_API_STUB(async_raid6_datap_recov);

#endif
/*
 * crypto/kdf_sp800108.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_KDF800108_CTR)

#include <crypto/kdf_sp800108.h>

DEFINE_CRYPTO_API_STUB(crypto_kdf108_ctr_generate);
DEFINE_CRYPTO_API_STUB(crypto_kdf108_setkey);

#endif
/*
 * crypto/krb5/krb5.o
 */
#if IS_BUILTIN(CONFIG_CRYPTO_KRB5)

#include <crypto/krb5.h>

/*
 * crypto/krb5/krb5_kdf.c
 */
DEFINE_CRYPTO_API_STUB(crypto_krb5_calc_PRFplus);

/*
 * crypto/krb5/krb5_api.c
 */
DEFINE_CRYPTO_API_STUB(crypto_krb5_find_enctype);
DEFINE_CRYPTO_API_STUB(crypto_krb5_how_much_buffer);
DEFINE_CRYPTO_API_STUB(crypto_krb5_how_much_data);
DEFINE_CRYPTO_API_STUB(crypto_krb5_where_is_the_data);
DEFINE_CRYPTO_API_STUB(crypto_krb5_prepare_encryption);
DEFINE_CRYPTO_API_STUB(crypto_krb5_prepare_checksum);
DEFINE_CRYPTO_API_STUB(crypto_krb5_encrypt);
DEFINE_CRYPTO_API_STUB(crypto_krb5_decrypt);
DEFINE_CRYPTO_API_STUB(crypto_krb5_get_mic);
DEFINE_CRYPTO_API_STUB(crypto_krb5_verify_mic);

#endif
/*
 * crypto/ecdh_helper.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_ECDH)

#include <crypto/ecdh.h>

DEFINE_CRYPTO_API_STUB(crypto_ecdh_key_len);
DEFINE_CRYPTO_API_STUB(crypto_ecdh_encode_key);
DEFINE_CRYPTO_API_STUB(crypto_ecdh_decode_key);

#endif
/*
 * crypto/asymmetric_keys/verify_pefile.c
 */
#if IS_BUILTIN(CONFIG_SIGNED_PE_FILE_VERIFICATION)

#include <linux/verification.h>

DEFINE_CRYPTO_API_STUB(verify_pefile_signature);

#endif