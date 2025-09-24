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

/*
 * arch/x86/crypto/camellia_aesni_avx_glue.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_CAMELLIA_AESNI_AVX_X86_64)

#include <arch/x86/crypto/camellia.h>

DEFINE_CRYPTO_API_STUB(camellia_ecb_enc_16way);
DEFINE_CRYPTO_API_STUB(camellia_ecb_dec_16way);
DEFINE_CRYPTO_API_STUB(camellia_cbc_dec_16way);

#endif

/*
 * arch/x86/crypto/sm4_aesni_avx_glue.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_SM4_AESNI_AVX_X86_64)

#include <arch/x86/crypto/sm4-avx.h>

DEFINE_CRYPTO_API_STUB(sm4_avx_ecb_encrypt);
DEFINE_CRYPTO_API_STUB(sm4_avx_ecb_decrypt);
DEFINE_CRYPTO_API_STUB(sm4_cbc_encrypt);
DEFINE_CRYPTO_API_STUB(sm4_avx_cbc_decrypt);
DEFINE_CRYPTO_API_STUB(sm4_avx_ctr_crypt);

#endif

/*
 * arch/x86/crypto/aria_aesni_avx_glue.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_ARIA_AESNI_AVX_X86_64)

#include <arch/x86/crypto/aria-avx.h>

DEFINE_CRYPTO_API_STUB(aria_aesni_avx_encrypt_16way);
DEFINE_CRYPTO_API_STUB(aria_aesni_avx_decrypt_16way);
DEFINE_CRYPTO_API_STUB(aria_aesni_avx_ctr_crypt_16way);
#ifdef CONFIG_AS_GFNI
DEFINE_CRYPTO_API_STUB(aria_aesni_avx_gfni_encrypt_16way);
DEFINE_CRYPTO_API_STUB(aria_aesni_avx_gfni_decrypt_16way);
DEFINE_CRYPTO_API_STUB(aria_aesni_avx_gfni_ctr_crypt_16way);
#endif /* CONFIG_AS_GFNI */

#endif

/*
 * arch/x86/crypto/aria_aesni_avx2_glue.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_ARIA_AESNI_AVX2_X86_64)

#include <arch/x86/crypto/aria-avx.h>

DEFINE_CRYPTO_API_STUB(aria_aesni_avx2_encrypt_32way);
DEFINE_CRYPTO_API_STUB(aria_aesni_avx2_decrypt_32way);
DEFINE_CRYPTO_API_STUB(aria_aesni_avx2_ctr_crypt_32way);
#ifdef CONFIG_AS_GFNI
DEFINE_CRYPTO_API_STUB(aria_aesni_avx2_gfni_encrypt_32way);
DEFINE_CRYPTO_API_STUB(aria_aesni_avx2_gfni_decrypt_32way);
DEFINE_CRYPTO_API_STUB(aria_aesni_avx2_gfni_ctr_crypt_32way);
#endif /* CONFIG_AS_GFNI */

#endif