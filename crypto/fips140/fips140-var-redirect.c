// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Variable redirect stubs for the FIPS140 pluggable interface.
 * These create pointer indirections in vmlinux for variables that
 * are defined in fips140.ko, allowing vmlinux code to access them
 * through CRYPTO_VAR_NAME() pointers populated at module load time.
 */

/*
 * crypto/api.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO)

#include "../internal.h"

#undef crypto_alg_list
#undef crypto_alg_sem
DEFINE_CRYPTO_VAR_STUB(crypto_alg_list);
DEFINE_CRYPTO_VAR_STUB(crypto_alg_sem);

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
 * crypto/fips.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_FIPS)

#include <linux/fips.h>

#undef fips_fail_notif_chain
DEFINE_CRYPTO_VAR_STUB(fips_fail_notif_chain);

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



