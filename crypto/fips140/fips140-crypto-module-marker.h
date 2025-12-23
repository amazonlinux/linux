#ifndef _FIPS140_CRYPTO_MODULE_MARKER_H
#define _FIPS140_CRYPTO_MODULE_MARKER_H

/* Crypto module marker - automatically included for crypto-objs-m modules */
static const char __fips140_crypto_marker[] 
    __attribute__((section(".fips140_crypto_marker"), used)) = "FIPS140_CRYPTO_OBJS_M";

#endif /* _FIPS140_CRYPTO_MODULE_MARKER_H */
