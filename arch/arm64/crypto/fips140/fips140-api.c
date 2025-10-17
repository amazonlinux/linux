/*
 * arch/arm64/crypto/sm4-ce-glue.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_SM4_ARM64_CE_BLK)

#include <arch/arm64/crypto/sm4-ce.h>

DEFINE_CRYPTO_API_STUB(sm4_ce_expand_key);
DEFINE_CRYPTO_API_STUB(sm4_ce_crypt_block);
DEFINE_CRYPTO_API_STUB(sm4_ce_cbc_enc);

#endif

/*
 * arch/arm64/crypto/aes-ce-glue.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_AES_ARM64_CE)

#include <arch/arm64/crypto/aes-ce-setkey.h>

DEFINE_CRYPTO_API_STUB(ce_aes_setkey);
DEFINE_CRYPTO_API_STUB(ce_aes_expandkey);

#endif
