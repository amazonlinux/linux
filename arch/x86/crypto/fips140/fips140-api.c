/*
 * arch/x86/crypto/curve25519-x86_64.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_CURVE25519_X86)

#include <crypto/curve25519.h>

DEFINE_CRYPTO_API_STUB(curve25519_arch);
DEFINE_CRYPTO_API_STUB(curve25519_base_arch);

#endif

/*
 * arch/x86/crypto/twofish_glue.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_TWOFISH_X86_64)

#include <arch/x86/crypto/twofish.h>

DEFINE_CRYPTO_API_STUB(twofish_enc_blk);
DEFINE_CRYPTO_API_STUB(twofish_dec_blk);

#endif

/*
 * arch/x86/crypto/twofish_glue_3way.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_TWOFISH_X86_64_3WAY)

#include <arch/x86/crypto/twofish.h>

DEFINE_CRYPTO_API_STUB(__twofish_enc_blk_3way);
DEFINE_CRYPTO_API_STUB(twofish_dec_blk_3way);
DEFINE_CRYPTO_API_STUB(twofish_dec_blk_cbc_3way);

#endif

/*
 * arch/x86/crypto/serpent_avx_glue.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_SERPENT_AVX_X86_64)

#include <arch/x86/crypto/serpent-avx.h>

DEFINE_CRYPTO_API_STUB(serpent_ecb_enc_8way_avx);
DEFINE_CRYPTO_API_STUB(serpent_ecb_dec_8way_avx);
DEFINE_CRYPTO_API_STUB(serpent_cbc_dec_8way_avx);

#endif

/*
 * arch/x86/crypto/camellia_glue.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_CAMELLIA_X86_64)

#include <arch/x86/crypto/camellia.h>

DEFINE_CRYPTO_API_STUB(__camellia_setkey);
DEFINE_CRYPTO_API_STUB(__camellia_enc_blk);
DEFINE_CRYPTO_API_STUB(camellia_dec_blk);
DEFINE_CRYPTO_API_STUB(__camellia_enc_blk_2way);
DEFINE_CRYPTO_API_STUB(camellia_dec_blk_2way);
DEFINE_CRYPTO_API_STUB(camellia_decrypt_cbc_2way);

#endif