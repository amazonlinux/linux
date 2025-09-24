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