/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * FIPS 140 Kernel Cryptographic Module - Header File
 */

#ifndef _CRYPTO_FIPS140_MODULE_H
#define _CRYPTO_FIPS140_MODULE_H

#include <linux/completion.h>
#include <linux/sched.h>

/* Completion to signal that self-tests are done */
extern struct completion fips140_tests_done;

/* The thread that is initializing the FIPS module */
extern struct task_struct *fips140_init_thread;

/* FIPS 140 algorithm specification structure */
struct fips140_alg {
	/*
	 * Either cra_name or cra_driver_name is set.
	 *
	 * cra_name makes the entry match all software implementations of a
	 * given algorithm. This is used when the module is meant to replace
	 * *all* software implementations of the algorithm.
	 *
	 * cra_driver_name makes the entry match a single implementation of an
	 * algorithm. This is used for specific algorithm implementations.
	 */
	const char *cra_name;
	const char *cra_driver_name;

	/*
	 * approved is true if fips140_is_approved_service() should return that
	 * the algorithm is approved.
	 */
	bool approved;

	/*
	 * unregistered_inkern gets set to true at runtime if at least one
	 * algorithm matching this entry was unregistered from the kernel.
	 */
	bool unregistered_inkern;
};

/*
 * fips140_algs[] lists the algorithms that this module unregisters from the
 * kernel crypto API so that it can register its own implementation(s) of them.
 *
 * We only unregister algorithms that we actually provide in fips140.ko to
 * avoid breaking kernel functionality.
 */
static struct fips140_alg fips140_algs[] = {
	/* 
	 * FIPS 140-3 Approved Algorithms
	 * These are cryptographic algorithms that are FIPS 140-3 approved
	 */
	
	/* AES algorithms - FIPS approved */
#if defined(CONFIG_CRYPTO_AES) && !IS_MODULE(CONFIG_CRYPTO_AES)
	{ .cra_name = "aes", .approved = true },
#endif
	{ .cra_name = "cbc(aes)", .approved = true },
	{ .cra_name = "ctr(aes)", .approved = true },
	{ .cra_name = "ecb(aes)", .approved = true },
	{ .cra_name = "xts(aes)", .approved = true },
	{ .cra_name = "gcm(aes)", .approved = true },
	{ .cra_name = "ccm(aes)", .approved = true },
	{ .cra_name = "cmac(aes)", .approved = true },
	{ .cra_name = "xcbc(aes)", .approved = true },
	{ .cra_name = "cts(cbc(aes))", .approved = true },

	/* SHA algorithms - FIPS approved */
	{ .cra_name = "sha1", .approved = true },
	{ .cra_name = "sha224", .approved = true },
	{ .cra_name = "sha256", .approved = true },
	{ .cra_name = "sha384", .approved = true },
	{ .cra_name = "sha512", .approved = true },
	{ .cra_name = "sha3-224", .approved = true },
	{ .cra_name = "sha3-256", .approved = true },
	{ .cra_name = "sha3-384", .approved = true },
	{ .cra_name = "sha3-512", .approved = true },

	/* HMAC algorithms - FIPS approved */
	{ .cra_name = "hmac(sha1)", .approved = true },
	{ .cra_name = "hmac(sha224)", .approved = true },
	{ .cra_name = "hmac(sha256)", .approved = true },
	{ .cra_name = "hmac(sha384)", .approved = true },
	{ .cra_name = "hmac(sha512)", .approved = true },

	/* DRBG - FIPS approved */
	{ .cra_name = "stdrng", .approved = true },
	{ .cra_name = "drbg_nopr_ctr_aes128", .approved = true },
	{ .cra_name = "drbg_nopr_ctr_aes192", .approved = true },
	{ .cra_name = "drbg_nopr_ctr_aes256", .approved = true },
	{ .cra_name = "drbg_pr_ctr_aes128", .approved = true },
	{ .cra_name = "drbg_pr_ctr_aes192", .approved = true },
	{ .cra_name = "drbg_pr_ctr_aes256", .approved = true },

	/* RSA - FIPS approved */
#if defined(CONFIG_CRYPTO_RSA) && !IS_MODULE(CONFIG_CRYPTO_RSA)
	{ .cra_name = "rsa", .approved = true },
	{ .cra_name = "pkcs1pad(rsa)", .approved = true },
#endif

	/* ECDSA/ECDH - FIPS approved */
#if defined(CONFIG_CRYPTO_ECDSA) && !IS_MODULE(CONFIG_CRYPTO_ECDSA)
	{ .cra_name = "ecdsa", .approved = true },
#endif
#if defined(CONFIG_CRYPTO_ECDH) && !IS_MODULE(CONFIG_CRYPTO_ECDH)
	{ .cra_name = "ecdh", .approved = true },
#endif

	/* DH - FIPS approved */
#if defined(CONFIG_CRYPTO_DH) && !IS_MODULE(CONFIG_CRYPTO_DH)
	{ .cra_name = "dh", .approved = true },
#endif

	/*
	 * Non-FIPS Approved Algorithms
	 * These algorithms are included in the module but are not FIPS approved
	 */

	/* Block ciphers - non-approved */
#if defined(CONFIG_CRYPTO_AES_TI) && !IS_MODULE(CONFIG_CRYPTO_AES_TI)
	{ .cra_name = "aes-ti", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_ANUBIS) && !IS_MODULE(CONFIG_CRYPTO_ANUBIS)
	{ .cra_name = "anubis", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_ARC4) && !IS_MODULE(CONFIG_CRYPTO_ARC4)
	{ .cra_name = "arc4", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_ARIA) && !IS_MODULE(CONFIG_CRYPTO_ARIA)
	{ .cra_name = "aria", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_BLOWFISH) && !IS_MODULE(CONFIG_CRYPTO_BLOWFISH)
	{ .cra_name = "blowfish", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_CAMELLIA) && !IS_MODULE(CONFIG_CRYPTO_CAMELLIA)
	{ .cra_name = "camellia", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_CAST5) && !IS_MODULE(CONFIG_CRYPTO_CAST5)
	{ .cra_name = "cast5", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_CAST6) && !IS_MODULE(CONFIG_CRYPTO_CAST6)
	{ .cra_name = "cast6", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_CHACHA20) && !IS_MODULE(CONFIG_CRYPTO_CHACHA20)
	{ .cra_name = "chacha20", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_DES) && !IS_MODULE(CONFIG_CRYPTO_DES)
	{ .cra_name = "des", .approved = false },
	{ .cra_name = "des3_ede", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_FCRYPT) && !IS_MODULE(CONFIG_CRYPTO_FCRYPT)
	{ .cra_name = "fcrypt", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_KHAZAD) && !IS_MODULE(CONFIG_CRYPTO_KHAZAD)
	{ .cra_name = "khazad", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_SEED) && !IS_MODULE(CONFIG_CRYPTO_SEED)
	{ .cra_name = "seed", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_SERPENT) && !IS_MODULE(CONFIG_CRYPTO_SERPENT)
	{ .cra_name = "serpent", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_SM4) && !IS_MODULE(CONFIG_CRYPTO_SM4)
	{ .cra_name = "sm4", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_TEA) && !IS_MODULE(CONFIG_CRYPTO_TEA)
	{ .cra_name = "tea", .approved = false },
	{ .cra_name = "xtea", .approved = false },
	{ .cra_name = "xeta", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_TWOFISH) && !IS_MODULE(CONFIG_CRYPTO_TWOFISH)
	{ .cra_name = "twofish", .approved = false },
#endif

	/* Hash algorithms - non-approved */
	{ .cra_name = "blake2b-160", .approved = false },
	{ .cra_name = "blake2b-256", .approved = false },
	{ .cra_name = "blake2b-384", .approved = false },
	{ .cra_name = "blake2b-512", .approved = false },
	{ .cra_name = "md4", .approved = false },
	{ .cra_name = "md5", .approved = false },
	{ .cra_name = "rmd160", .approved = false },
	{ .cra_name = "sm3", .approved = false },
	{ .cra_name = "streebog256", .approved = false },
	{ .cra_name = "streebog512", .approved = false },
	{ .cra_name = "wp256", .approved = false },
	{ .cra_name = "wp384", .approved = false },
	{ .cra_name = "wp512", .approved = false },
#if defined(CONFIG_CRYPTO_XXHASH) && !IS_MODULE(CONFIG_CRYPTO_XXHASH)
	{ .cra_name = "xxhash64", .approved = false },
#endif

	/* CRC algorithms - non-approved */
#if defined(CONFIG_CRYPTO_CRC32) && !IS_MODULE(CONFIG_CRYPTO_CRC32)
	{ .cra_name = "crc32", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_CRC32C) && !IS_MODULE(CONFIG_CRYPTO_CRC32C)
	{ .cra_name = "crc32c", .approved = false },
#endif

	/* Compression algorithms - non-approved */
#if defined(CONFIG_CRYPTO_842) && !IS_MODULE(CONFIG_CRYPTO_842)
	{ .cra_name = "842", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_DEFLATE) && !IS_MODULE(CONFIG_CRYPTO_DEFLATE)
	{ .cra_name = "deflate", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_LZ4) && !IS_MODULE(CONFIG_CRYPTO_LZ4)
	{ .cra_name = "lz4", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_LZ4HC) && !IS_MODULE(CONFIG_CRYPTO_LZ4HC)
	{ .cra_name = "lz4hc", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_LZO) && !IS_MODULE(CONFIG_CRYPTO_LZO)
	{ .cra_name = "lzo", .approved = false },
	{ .cra_name = "lzo-rle", .approved = false },
#endif
#if defined(CONFIG_ZSTD_COMPRESS) && !IS_MODULE(CONFIG_ZSTD_COMPRESS)
	{ .cra_name = "zstd", .approved = false },
#endif

	/* AEAD algorithms - non-approved (except GCM) */
	{ .cra_name = "aegis128", .approved = false },
	{ .cra_name = "authenc(hmac(sha1),cbc(aes))", .approved = false },
	{ .cra_name = "authenc(hmac(sha256),cbc(aes))", .approved = false },
	{ .cra_name = "authenc(hmac(sha512),cbc(aes))", .approved = false },
	{ .cra_name = "authencesn(hmac(sha1),cbc(aes))", .approved = false },
	{ .cra_name = "authencesn(hmac(sha256),cbc(aes))", .approved = false },
	{ .cra_name = "authencesn(hmac(sha512),cbc(aes))", .approved = false },
#if defined(CONFIG_CRYPTO_CHACHA20POLY1305) && !IS_MODULE(CONFIG_CRYPTO_CHACHA20POLY1305)
	{ .cra_name = "chacha20poly1305", .approved = false },
	{ .cra_name = "xchacha20poly1305", .approved = false },
#endif

	/* Stream ciphers - non-approved */
#if defined(CONFIG_CRYPTO_CHACHA20) && !IS_MODULE(CONFIG_CRYPTO_CHACHA20)
	{ .cra_name = "chacha20", .approved = false },
	{ .cra_name = "xchacha20", .approved = false },
	{ .cra_name = "xchacha12", .approved = false },
#endif

	/* Block cipher modes - non-approved */
#if defined(CONFIG_CRYPTO_ADIANTUM) && !IS_MODULE(CONFIG_CRYPTO_ADIANTUM)
	{ .cra_name = "adiantum(xchacha12,aes)", .approved = false },
#endif
	{ .cra_name = "essiv(cbc(aes),sha256)", .approved = false },
	{ .cra_name = "hctr2(aes)", .approved = false },
	{ .cra_name = "lrw(aes)", .approved = false },
	{ .cra_name = "pcbc(aes)", .approved = false },

	/* MAC algorithms - non-approved (except CMAC/HMAC) */
#if defined(CONFIG_CRYPTO_MICHAEL_MIC) && !IS_MODULE(CONFIG_CRYPTO_MICHAEL_MIC)
	{ .cra_name = "michael_mic", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_POLY1305) && !IS_MODULE(CONFIG_CRYPTO_POLY1305)
	{ .cra_name = "poly1305", .approved = false },
#endif
	{ .cra_name = "polyval", .approved = false },
	{ .cra_name = "ghash", .approved = false },
	{ .cra_name = "nhpoly1305", .approved = false },

	/* KDF algorithms - non-approved */
	{ .cra_name = "hkdf(sha1)", .approved = false },
	{ .cra_name = "hkdf(sha256)", .approved = false },
	{ .cra_name = "hkdf(sha512)", .approved = false },
	{ .cra_name = "kdf_sp800108_ctr(hmac(sha256))", .approved = false },

	/* Elliptic curve algorithms - non-approved */
#if defined(CONFIG_CRYPTO_CURVE25519) && !IS_MODULE(CONFIG_CRYPTO_CURVE25519)
	{ .cra_name = "curve25519", .approved = false },
#endif
#if defined(CONFIG_CRYPTO_ECRDSA) && !IS_MODULE(CONFIG_CRYPTO_ECRDSA)
	{ .cra_name = "ecrdsa", .approved = false },
#endif

	/* RNG algorithms - non-approved (except DRBG) */
	{ .cra_name = "jitterentropy_rng", .approved = false },

	/* Null algorithm - non-approved */
	{ .cra_name = "cipher_null", .approved = false },
	{ .cra_name = "compress_null", .approved = false },
	{ .cra_name = "digest_null", .approved = false },

	/* Template algorithms - non-approved */
	{ .cra_name = "cryptd", .approved = false },
	{ .cra_name = "pcrypt", .approved = false },

	/* KRB5 algorithms - non-approved */
#if defined(CONFIG_CRYPTO_KRB5ENC) && !IS_MODULE(CONFIG_CRYPTO_KRB5ENC)
	{ .cra_name = "krb5enc", .approved = false },
#endif
};

/* FIPS 140-3 service indicator */
bool fips140_is_approved_service(const char *name);

/* FIPS 140-3 module version information */
const char *fips140_module_version(void);

#endif /* _CRYPTO_FIPS140_MODULE_H */
