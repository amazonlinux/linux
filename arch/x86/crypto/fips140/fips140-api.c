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