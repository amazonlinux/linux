/*
 * arch/arm64/crypto/sm4-ce-glue.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_SM4_ARM64_CE_BLK)

#include <arch/arm64/crypto/sm4-ce.h>

DEFINE_CRYPTO_API_STUB(sm4_ce_expand_key);
DEFINE_CRYPTO_API_STUB(sm4_ce_crypt_block);
DEFINE_CRYPTO_API_STUB(sm4_ce_cbc_enc);

#endif
