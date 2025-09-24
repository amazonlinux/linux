/*
 * arch/x86/crypto/curve25519-x86_64.c
 */
#if IS_BUILTIN(CONFIG_CRYPTO_CURVE25519_X86)

#include <crypto/curve25519.h>

DEFINE_CRYPTO_API_STUB(curve25519_arch);
DEFINE_CRYPTO_API_STUB(curve25519_base_arch);

#endif