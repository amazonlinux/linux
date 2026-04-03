// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Variable redirect stubs for the FIPS140 pluggable interface.
 * These create pointer indirections in vmlinux for variables that
 * are defined in fips140.ko, allowing vmlinux code to access them
 * through CRYPTO_VAR_NAME() pointers populated at module load time.
 */

/*
 * crypto/md5.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_MD5)

#include <crypto/md5.h>

#undef md5_zero_message_hash
DEFINE_CRYPTO_VAR_STUB(md5_zero_message_hash);

#endif

/*
 * crypto/rng.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_RNG2)

#include <crypto/rng.h>

#undef crypto_default_rng
DEFINE_CRYPTO_VAR_STUB(crypto_default_rng);

#endif

/*
 * crypto/asymmetric_keys/asymmetric_type.c
 */
#if IS_BUILTIN(CONFIG_ASYMMETRIC_KEY_TYPE)

#include <keys/asymmetric-type.h>

#undef key_type_asymmetric
DEFINE_CRYPTO_VAR_STUB(key_type_asymmetric);

#endif

/*
 * crypto/asymmetric_keys/public_key.c
 */
#if IS_BUILTIN(CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE)

#include <crypto/public_key.h>

#undef public_key_subtype
DEFINE_CRYPTO_VAR_STUB(public_key_subtype);

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
