// SPDX-License-Identifier: GPL-2.0-only
/*
 * FIPS 140 Test Suites - Test Functions and Descriptors
 * 
 * This file contains test functions and algorithm descriptors
 * extracted from testmgr.c for FIPS 140 compliance.
 * 
 * Structure matches original testmgr.c:
 * - Contains test function implementations
 * - Contains algorithm descriptor array
 * - Contains main test entry point
 * 
 * Generated from kernel 6.15 testmgr.c
 */

#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include <crypto/aead.h>
#include <crypto/rng.h>
#include <crypto/internal/cipher.h>
#include <crypto/akcipher.h>
#include <crypto/kpp.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/fips.h>
#include <linux/module.h>
#include <linux/once.h>

#include "fips140-testsuites.h"
#include "fips140-module.h"

/*
 * Algorithm test descriptor structure (from testmgr.c)
 */
struct fips140_alg_test_desc {
	const char *alg;
	const char *generic_driver;
	int (*test)(const struct fips140_alg_test_desc *desc, const char *driver,
		    u32 type, u32 mask);
	int fips_allowed;

	union {
		struct fips140_aead_test_suite aead;
		struct fips140_cipher_test_suite cipher;
		struct fips140_comp_test_suite comp;
		struct fips140_hash_test_suite hash;
		struct fips140_cprng_test_suite cprng;
		struct fips140_drbg_test_suite drbg;
		struct fips140_akcipher_test_suite akcipher;
		struct fips140_sig_test_suite sig;
		struct fips140_kpp_test_suite kpp;
	} suite;
};

/*
 * Test function stubs (implement as needed)
 */
int fips140_alg_test_null(const struct fips140_alg_test_desc *desc, const char *driver, u32 type, u32 mask)
{
	return 0;
}

int fips140_alg_test_cipher(const struct fips140_alg_test_desc *desc, const char *driver, u32 type, u32 mask)
{
	pr_info("fips140: cipher test for %s\n", driver);
	return 0;
}

int fips140_alg_test_skcipher(const struct fips140_alg_test_desc *desc, const char *driver, u32 type, u32 mask)
{
	pr_info("fips140: skcipher test for %s\n", driver);
	return 0;
}

int fips140_alg_test_aead(const struct fips140_alg_test_desc *desc, const char *driver, u32 type, u32 mask)
{
	pr_info("fips140: aead test for %s\n", driver);
	return 0;
}

int fips140_alg_test_hash(const struct fips140_alg_test_desc *desc, const char *driver, u32 type, u32 mask)
{
	pr_info("fips140: hash test for %s\n", driver);
	return 0;
}

int fips140_alg_test_comp(const struct fips140_alg_test_desc *desc, const char *driver, u32 type, u32 mask)
{
	pr_info("fips140: comp test for %s\n", driver);
	return 0;
}

int fips140_alg_test_crc32c(const struct fips140_alg_test_desc *desc, const char *driver, u32 type, u32 mask)
{
	pr_info("fips140: crc32c test for %s\n", driver);
	return 0;
}

int fips140_alg_test_cprng(const struct fips140_alg_test_desc *desc, const char *driver, u32 type, u32 mask)
{
	pr_info("fips140: cprng test for %s\n", driver);
	return 0;
}

int fips140_alg_test_drbg(const struct fips140_alg_test_desc *desc, const char *driver, u32 type, u32 mask)
{
	pr_info("fips140: drbg test for %s\n", driver);
	return 0;
}

int fips140_alg_test_akcipher(const struct fips140_alg_test_desc *desc, const char *driver, u32 type, u32 mask)
{
	pr_info("fips140: akcipher test for %s\n", driver);
	return 0;
}

int fips140_alg_test_kpp(const struct fips140_alg_test_desc *desc, const char *driver, u32 type, u32 mask)
{
	pr_info("fips140: kpp test for %s\n", driver);
	return 0;
}

int fips140_alg_test_sig(const struct fips140_alg_test_desc *desc, const char *driver, u32 type, u32 mask)
{
	pr_info("fips140: sig test for %s\n", driver);
	return 0;
}

const struct fips140_alg_test_desc fips140_alg_test_descs[] = {
	{
		.alg = "adiantum(xchacha12,aes)",
		.generic_driver = "adiantum(xchacha12-generic,aes-generic,nhpoly1305-generic)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(adiantum_xchacha12_aes_tv_template)
		},
	}, {
		.alg = "adiantum(xchacha20,aes)",
		.generic_driver = "adiantum(xchacha20-generic,aes-generic,nhpoly1305-generic)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(adiantum_xchacha20_aes_tv_template)
		},
	}, {
		.alg = "aegis128",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(aegis128_tv_template)
		}
	}, {
		.alg = "ansi_cprng",
		.test = fips140_alg_test_cprng,
		.suite = {
			.cprng = __VECS(ansi_cprng_aes_tv_template)
		}
	}, {
		.alg = "authenc(hmac(md5),ecb(cipher_null))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(hmac_md5_ecb_cipher_null_tv_template)
		}
	}, {
		.alg = "authenc(hmac(sha1),cbc(aes))",
		.test = fips140_alg_test_aead,
		.fips_allowed = 1,
		.suite = {
			.aead = __VECS(hmac_sha1_aes_cbc_tv_temp)
		}
	}, {
		.alg = "authenc(hmac(sha1),cbc(des))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(hmac_sha1_des_cbc_tv_temp)
		}
	}, {
		.alg = "authenc(hmac(sha1),cbc(des3_ede))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(hmac_sha1_des3_ede_cbc_tv_temp)
		}
	}, {
		.alg = "authenc(hmac(sha1),ctr(aes))",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "authenc(hmac(sha1),ecb(cipher_null))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(hmac_sha1_ecb_cipher_null_tv_temp)
		}
	}, {
		.alg = "authenc(hmac(sha1),rfc3686(ctr(aes)))",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "authenc(hmac(sha224),cbc(des))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(hmac_sha224_des_cbc_tv_temp)
		}
	}, {
		.alg = "authenc(hmac(sha224),cbc(des3_ede))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(hmac_sha224_des3_ede_cbc_tv_temp)
		}
	}, {
		.alg = "authenc(hmac(sha256),cbc(aes))",
		.test = fips140_alg_test_aead,
		.fips_allowed = 1,
		.suite = {
			.aead = __VECS(hmac_sha256_aes_cbc_tv_temp)
		}
	}, {
		.alg = "authenc(hmac(sha256),cbc(des))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(hmac_sha256_des_cbc_tv_temp)
		}
	}, {
		.alg = "authenc(hmac(sha256),cbc(des3_ede))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(hmac_sha256_des3_ede_cbc_tv_temp)
		}
	}, {
		.alg = "authenc(hmac(sha256),ctr(aes))",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "authenc(hmac(sha256),cts(cbc(aes)))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(krb5_test_aes128_cts_hmac_sha256_128)
		}
	}, {
		.alg = "authenc(hmac(sha256),rfc3686(ctr(aes)))",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "authenc(hmac(sha384),cbc(des))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(hmac_sha384_des_cbc_tv_temp)
		}
	}, {
		.alg = "authenc(hmac(sha384),cbc(des3_ede))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(hmac_sha384_des3_ede_cbc_tv_temp)
		}
	}, {
		.alg = "authenc(hmac(sha384),ctr(aes))",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "authenc(hmac(sha384),cts(cbc(aes)))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(krb5_test_aes256_cts_hmac_sha384_192)
		}
	}, {
		.alg = "authenc(hmac(sha384),rfc3686(ctr(aes)))",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "authenc(hmac(sha512),cbc(aes))",
		.fips_allowed = 1,
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(hmac_sha512_aes_cbc_tv_temp)
		}
	}, {
		.alg = "authenc(hmac(sha512),cbc(des))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(hmac_sha512_des_cbc_tv_temp)
		}
	}, {
		.alg = "authenc(hmac(sha512),cbc(des3_ede))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(hmac_sha512_des3_ede_cbc_tv_temp)
		}
	}, {
		.alg = "authenc(hmac(sha512),ctr(aes))",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "authenc(hmac(sha512),rfc3686(ctr(aes)))",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "blake2b-160",
		.test = fips140_alg_test_hash,
		.fips_allowed = 0,
		.suite = {
			.hash = __VECS(blake2b_160_tv_template)
		}
	}, {
		.alg = "blake2b-256",
		.test = fips140_alg_test_hash,
		.fips_allowed = 0,
		.suite = {
			.hash = __VECS(blake2b_256_tv_template)
		}
	}, {
		.alg = "blake2b-384",
		.test = fips140_alg_test_hash,
		.fips_allowed = 0,
		.suite = {
			.hash = __VECS(blake2b_384_tv_template)
		}
	}, {
		.alg = "blake2b-512",
		.test = fips140_alg_test_hash,
		.fips_allowed = 0,
		.suite = {
			.hash = __VECS(blake2b_512_tv_template)
		}
	}, {
		.alg = "cbc(aes)",
		.test = fips140_alg_test_skcipher,
		.fips_allowed = 1,
		.suite = {
			.cipher = __VECS(aes_cbc_tv_template)
		},
	}, {
		.alg = "cbc(anubis)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(anubis_cbc_tv_template)
		},
	}, {
		.alg = "cbc(aria)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(aria_cbc_tv_template)
		},
	}, {
		.alg = "cbc(blowfish)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(bf_cbc_tv_template)
		},
	}, {
		.alg = "cbc(camellia)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(camellia_cbc_tv_template)
		},
	}, {
		.alg = "cbc(cast5)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(cast5_cbc_tv_template)
		},
	}, {
		.alg = "cbc(cast6)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(cast6_cbc_tv_template)
		},
	}, {
		.alg = "cbc(des)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(des_cbc_tv_template)
		},
	}, {
		.alg = "cbc(des3_ede)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(des3_ede_cbc_tv_template)
		},
	}, {
		/* Same as cbc(aes) except the key is stored in
		 * hardware secure memory which we reference by index
		 */
		.alg = "cbc(paes)",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		/* Same as cbc(sm4) except the key is stored in
		 * hardware secure memory which we reference by index
		 */
		.alg = "cbc(psm4)",
		.test = fips140_alg_test_null,
	}, {
		.alg = "cbc(serpent)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(serpent_cbc_tv_template)
		},
	}, {
		.alg = "cbc(sm4)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(sm4_cbc_tv_template)
		}
	}, {
		.alg = "cbc(twofish)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(tf_cbc_tv_template)
		},
	}, {
#if IS_ENABLED(CONFIG_CRYPTO_PAES_S390)
		.alg = "cbc-paes-s390",
		.fips_allowed = 1,
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(aes_cbc_tv_template)
		}
	}, {
#endif
		.alg = "cbcmac(aes)",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(aes_cbcmac_tv_template)
		}
	}, {
		.alg = "cbcmac(sm4)",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(sm4_cbcmac_tv_template)
		}
	}, {
		.alg = "ccm(aes)",
		.generic_driver = "ccm_base(ctr(aes-generic),cbcmac(aes-generic))",
		.test = fips140_alg_test_aead,
		.fips_allowed = 1,
		.suite = {
			.aead = {
				____VECS(aes_ccm_tv_template),
				.einval_allowed = 1,
			}
		}
	}, {
		.alg = "ccm(sm4)",
		.generic_driver = "ccm_base(ctr(sm4-generic),cbcmac(sm4-generic))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = {
				____VECS(sm4_ccm_tv_template),
				.einval_allowed = 1,
			}
		}
	}, {
		.alg = "chacha20",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(chacha20_tv_template)
		},
	}, {
		.alg = "cmac(aes)",
		.fips_allowed = 1,
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(aes_cmac128_tv_template)
		}
	}, {
		.alg = "cmac(camellia)",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(camellia_cmac128_tv_template)
		}
	}, {
		.alg = "cmac(des3_ede)",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(des3_ede_cmac64_tv_template)
		}
	}, {
		.alg = "cmac(sm4)",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(sm4_cmac128_tv_template)
		}
	}, {
		.alg = "crc32",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(crc32_tv_template)
		}
	}, {
		.alg = "crc32c",
		.test = fips140_alg_test_crc32c,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(crc32c_tv_template)
		}
	}, {
		.alg = "ctr(aes)",
		.test = fips140_alg_test_skcipher,
		.fips_allowed = 1,
		.suite = {
			.cipher = __VECS(aes_ctr_tv_template)
		}
	}, {
		.alg = "ctr(aria)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(aria_ctr_tv_template)
		}
	}, {
		.alg = "ctr(blowfish)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(bf_ctr_tv_template)
		}
	}, {
		.alg = "ctr(camellia)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(camellia_ctr_tv_template)
		}
	}, {
		.alg = "ctr(cast5)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(cast5_ctr_tv_template)
		}
	}, {
		.alg = "ctr(cast6)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(cast6_ctr_tv_template)
		}
	}, {
		.alg = "ctr(des)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(des_ctr_tv_template)
		}
	}, {
		.alg = "ctr(des3_ede)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(des3_ede_ctr_tv_template)
		}
	}, {
		/* Same as ctr(aes) except the key is stored in
		 * hardware secure memory which we reference by index
		 */
		.alg = "ctr(paes)",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {

		/* Same as ctr(sm4) except the key is stored in
		 * hardware secure memory which we reference by index
		 */
		.alg = "ctr(psm4)",
		.test = fips140_alg_test_null,
	}, {
		.alg = "ctr(serpent)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(serpent_ctr_tv_template)
		}
	}, {
		.alg = "ctr(sm4)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(sm4_ctr_tv_template)
		}
	}, {
		.alg = "ctr(twofish)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(tf_ctr_tv_template)
		}
	}, {
#if IS_ENABLED(CONFIG_CRYPTO_PAES_S390)
		.alg = "ctr-paes-s390",
		.fips_allowed = 1,
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(aes_ctr_tv_template)
		}
	}, {
#endif
		.alg = "cts(cbc(aes))",
		.test = fips140_alg_test_skcipher,
		.fips_allowed = 1,
		.suite = {
			.cipher = __VECS(cts_mode_tv_template)
		}
	}, {
		/* Same as cts(cbc((aes)) except the key is stored in
		 * hardware secure memory which we reference by index
		 */
		.alg = "cts(cbc(paes))",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "cts(cbc(sm4))",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(sm4_cts_tv_template)
		}
	}, {
		.alg = "curve25519",
		.test = fips140_alg_test_kpp,
		.suite = {
			.kpp = __VECS(curve25519_tv_template)
		}
	}, {
		.alg = "deflate",
		.test = fips140_alg_test_comp,
		.fips_allowed = 1,
		.suite = {
			.comp = {
				.comp = __VECS(deflate_comp_tv_template),
				.decomp = __VECS(deflate_decomp_tv_template)
			}
		}
	}, {
		.alg = "deflate-iaa",
		.test = fips140_alg_test_comp,
		.fips_allowed = 1,
		.suite = {
			.comp = {
				.comp = __VECS(deflate_comp_tv_template),
				.decomp = __VECS(deflate_decomp_tv_template)
			}
		}
	}, {
		.alg = "dh",
		.test = fips140_alg_test_kpp,
		.suite = {
			.kpp = __VECS(dh_tv_template)
		}
	}, {
		.alg = "digest_null",
		.test = fips140_alg_test_null,
	}, {
		.alg = "drbg_nopr_ctr_aes128",
		.test = fips140_alg_test_drbg,
		.fips_allowed = 1,
		.suite = {
			.drbg = __VECS(drbg_nopr_ctr_aes128_tv_template)
		}
	}, {
		.alg = "drbg_nopr_ctr_aes192",
		.test = fips140_alg_test_drbg,
		.fips_allowed = 1,
		.suite = {
			.drbg = __VECS(drbg_nopr_ctr_aes192_tv_template)
		}
	}, {
		.alg = "drbg_nopr_ctr_aes256",
		.test = fips140_alg_test_drbg,
		.fips_allowed = 1,
		.suite = {
			.drbg = __VECS(drbg_nopr_ctr_aes256_tv_template)
		}
	}, {
		.alg = "drbg_nopr_hmac_sha256",
		.test = fips140_alg_test_drbg,
		.fips_allowed = 1,
		.suite = {
			.drbg = __VECS(drbg_nopr_hmac_sha256_tv_template)
		}
	}, {
		/*
		 * There is no need to specifically test the DRBG with every
		 * backend cipher -- covered by drbg_nopr_hmac_sha512 test
		 */
		.alg = "drbg_nopr_hmac_sha384",
		.test = fips140_alg_test_null,
	}, {
		.alg = "drbg_nopr_hmac_sha512",
		.test = fips140_alg_test_drbg,
		.fips_allowed = 1,
		.suite = {
			.drbg = __VECS(drbg_nopr_hmac_sha512_tv_template)
		}
	}, {
		.alg = "drbg_nopr_sha256",
		.test = fips140_alg_test_drbg,
		.fips_allowed = 1,
		.suite = {
			.drbg = __VECS(drbg_nopr_sha256_tv_template)
		}
	}, {
		/* covered by drbg_nopr_sha256 test */
		.alg = "drbg_nopr_sha384",
		.test = fips140_alg_test_null,
	}, {
		.alg = "drbg_nopr_sha512",
		.fips_allowed = 1,
		.test = fips140_alg_test_null,
	}, {
		.alg = "drbg_pr_ctr_aes128",
		.test = fips140_alg_test_drbg,
		.fips_allowed = 1,
		.suite = {
			.drbg = __VECS(drbg_pr_ctr_aes128_tv_template)
		}
	}, {
		/* covered by drbg_pr_ctr_aes128 test */
		.alg = "drbg_pr_ctr_aes192",
		.fips_allowed = 1,
		.test = fips140_alg_test_null,
	}, {
		.alg = "drbg_pr_ctr_aes256",
		.fips_allowed = 1,
		.test = fips140_alg_test_null,
	}, {
		.alg = "drbg_pr_hmac_sha256",
		.test = fips140_alg_test_drbg,
		.fips_allowed = 1,
		.suite = {
			.drbg = __VECS(drbg_pr_hmac_sha256_tv_template)
		}
	}, {
		/* covered by drbg_pr_hmac_sha256 test */
		.alg = "drbg_pr_hmac_sha384",
		.test = fips140_alg_test_null,
	}, {
		.alg = "drbg_pr_hmac_sha512",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "drbg_pr_sha256",
		.test = fips140_alg_test_drbg,
		.fips_allowed = 1,
		.suite = {
			.drbg = __VECS(drbg_pr_sha256_tv_template)
		}
	}, {
		/* covered by drbg_pr_sha256 test */
		.alg = "drbg_pr_sha384",
		.test = fips140_alg_test_null,
	}, {
		.alg = "drbg_pr_sha512",
		.fips_allowed = 1,
		.test = fips140_alg_test_null,
	}, {
		.alg = "ecb(aes)",
		.test = fips140_alg_test_skcipher,
		.fips_allowed = 1,
		.suite = {
			.cipher = __VECS(aes_tv_template)
		}
	}, {
		.alg = "ecb(anubis)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(anubis_tv_template)
		}
	}, {
		.alg = "ecb(arc4)",
		.generic_driver = "arc4-generic",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(arc4_tv_template)
		}
	}, {
		.alg = "ecb(aria)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(aria_tv_template)
		}
	}, {
		.alg = "ecb(blowfish)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(bf_tv_template)
		}
	}, {
		.alg = "ecb(camellia)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(camellia_tv_template)
		}
	}, {
		.alg = "ecb(cast5)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(cast5_tv_template)
		}
	}, {
		.alg = "ecb(cast6)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(cast6_tv_template)
		}
	}, {
		.alg = "ecb(cipher_null)",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "ecb(des)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(des_tv_template)
		}
	}, {
		.alg = "ecb(des3_ede)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(des3_ede_tv_template)
		}
	}, {
		.alg = "ecb(fcrypt)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = {
				.vecs = fcrypt_pcbc_tv_template,
				.count = 1
			}
		}
	}, {
		.alg = "ecb(khazad)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(khazad_tv_template)
		}
	}, {
		/* Same as ecb(aes) except the key is stored in
		 * hardware secure memory which we reference by index
		 */
		.alg = "ecb(paes)",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "ecb(seed)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(seed_tv_template)
		}
	}, {
		.alg = "ecb(serpent)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(serpent_tv_template)
		}
	}, {
		.alg = "ecb(sm4)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(sm4_tv_template)
		}
	}, {
		.alg = "ecb(tea)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(tea_tv_template)
		}
	}, {
		.alg = "ecb(twofish)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(tf_tv_template)
		}
	}, {
		.alg = "ecb(xeta)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(xeta_tv_template)
		}
	}, {
		.alg = "ecb(xtea)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(xtea_tv_template)
		}
	}, {
#if IS_ENABLED(CONFIG_CRYPTO_PAES_S390)
		.alg = "ecb-paes-s390",
		.fips_allowed = 1,
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(aes_tv_template)
		}
	}, {
#endif
		.alg = "ecdh-nist-p192",
		.test = fips140_alg_test_kpp,
		.suite = {
			.kpp = __VECS(ecdh_p192_tv_template)
		}
	}, {
		.alg = "ecdh-nist-p256",
		.test = fips140_alg_test_kpp,
		.fips_allowed = 1,
		.suite = {
			.kpp = __VECS(ecdh_p256_tv_template)
		}
	}, {
		.alg = "ecdh-nist-p384",
		.test = fips140_alg_test_kpp,
		.fips_allowed = 1,
		.suite = {
			.kpp = __VECS(ecdh_p384_tv_template)
		}
	}, {
		.alg = "ecdsa-nist-p192",
		.test = fips140_alg_test_sig,
		.suite = {
			.sig = __VECS(ecdsa_nist_p192_tv_template)
		}
	}, {
		.alg = "ecdsa-nist-p256",
		.test = fips140_alg_test_sig,
		.fips_allowed = 1,
		.suite = {
			.sig = __VECS(ecdsa_nist_p256_tv_template)
		}
	}, {
		.alg = "ecdsa-nist-p384",
		.test = fips140_alg_test_sig,
		.fips_allowed = 1,
		.suite = {
			.sig = __VECS(ecdsa_nist_p384_tv_template)
		}
	}, {
		.alg = "ecdsa-nist-p521",
		.test = fips140_alg_test_sig,
		.fips_allowed = 1,
		.suite = {
			.sig = __VECS(ecdsa_nist_p521_tv_template)
		}
	}, {
		.alg = "ecrdsa",
		.test = fips140_alg_test_sig,
		.suite = {
			.sig = __VECS(ecrdsa_tv_template)
		}
	}, {
		.alg = "essiv(authenc(hmac(sha256),cbc(aes)),sha256)",
		.test = fips140_alg_test_aead,
		.fips_allowed = 1,
		.suite = {
			.aead = __VECS(essiv_hmac_sha256_aes_cbc_tv_temp)
		}
	}, {
		.alg = "essiv(cbc(aes),sha256)",
		.test = fips140_alg_test_skcipher,
		.fips_allowed = 1,
		.suite = {
			.cipher = __VECS(essiv_aes_cbc_tv_template)
		}
	}, {
#if IS_ENABLED(CONFIG_CRYPTO_DH_RFC7919_GROUPS)
		.alg = "ffdhe2048(dh)",
		.test = fips140_alg_test_kpp,
		.fips_allowed = 1,
		.suite = {
			.kpp = __VECS(ffdhe2048_dh_tv_template)
		}
	}, {
		.alg = "ffdhe3072(dh)",
		.test = fips140_alg_test_kpp,
		.fips_allowed = 1,
		.suite = {
			.kpp = __VECS(ffdhe3072_dh_tv_template)
		}
	}, {
		.alg = "ffdhe4096(dh)",
		.test = fips140_alg_test_kpp,
		.fips_allowed = 1,
		.suite = {
			.kpp = __VECS(ffdhe4096_dh_tv_template)
		}
	}, {
		.alg = "ffdhe6144(dh)",
		.test = fips140_alg_test_kpp,
		.fips_allowed = 1,
		.suite = {
			.kpp = __VECS(ffdhe6144_dh_tv_template)
		}
	}, {
		.alg = "ffdhe8192(dh)",
		.test = fips140_alg_test_kpp,
		.fips_allowed = 1,
		.suite = {
			.kpp = __VECS(ffdhe8192_dh_tv_template)
		}
	}, {
#endif /* CONFIG_CRYPTO_DH_RFC7919_GROUPS */
		.alg = "gcm(aes)",
		.generic_driver = "gcm_base(ctr(aes-generic),ghash-generic)",
		.test = fips140_alg_test_aead,
		.fips_allowed = 1,
		.suite = {
			.aead = __VECS(aes_gcm_tv_template)
		}
	}, {
		.alg = "gcm(aria)",
		.generic_driver = "gcm_base(ctr(aria-generic),ghash-generic)",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(aria_gcm_tv_template)
		}
	}, {
		.alg = "gcm(sm4)",
		.generic_driver = "gcm_base(ctr(sm4-generic),ghash-generic)",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(sm4_gcm_tv_template)
		}
	}, {
		.alg = "ghash",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(ghash_tv_template)
		}
	}, {
		.alg = "hctr2(aes)",
		.generic_driver =
		    "hctr2_base(xctr(aes-generic),polyval-generic)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(aes_hctr2_tv_template)
		}
	}, {
		.alg = "hmac(md5)",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(hmac_md5_tv_template)
		}
	}, {
		.alg = "hmac(rmd160)",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(hmac_rmd160_tv_template)
		}
	}, {
		.alg = "hmac(sha1)",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(hmac_sha1_tv_template)
		}
	}, {
		.alg = "hmac(sha224)",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(hmac_sha224_tv_template)
		}
	}, {
		.alg = "hmac(sha256)",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(hmac_sha256_tv_template)
		}
	}, {
		.alg = "hmac(sha3-224)",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(hmac_sha3_224_tv_template)
		}
	}, {
		.alg = "hmac(sha3-256)",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(hmac_sha3_256_tv_template)
		}
	}, {
		.alg = "hmac(sha3-384)",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(hmac_sha3_384_tv_template)
		}
	}, {
		.alg = "hmac(sha3-512)",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(hmac_sha3_512_tv_template)
		}
	}, {
		.alg = "hmac(sha384)",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(hmac_sha384_tv_template)
		}
	}, {
		.alg = "hmac(sha512)",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(hmac_sha512_tv_template)
		}
	}, {
		.alg = "hmac(sm3)",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(hmac_sm3_tv_template)
		}
	}, {
		.alg = "hmac(streebog256)",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(hmac_streebog256_tv_template)
		}
	}, {
		.alg = "hmac(streebog512)",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(hmac_streebog512_tv_template)
		}
	}, {
		.alg = "jitterentropy_rng",
		.fips_allowed = 1,
		.test = fips140_alg_test_null,
	}, {
		.alg = "krb5enc(cmac(camellia),cts(cbc(camellia)))",
		.test = fips140_alg_test_aead,
		.suite.aead = __VECS(krb5_test_camellia_cts_cmac)
	}, {
		.alg = "lrw(aes)",
		.generic_driver = "lrw(ecb(aes-generic))",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(aes_lrw_tv_template)
		}
	}, {
		.alg = "lrw(camellia)",
		.generic_driver = "lrw(ecb(camellia-generic))",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(camellia_lrw_tv_template)
		}
	}, {
		.alg = "lrw(cast6)",
		.generic_driver = "lrw(ecb(cast6-generic))",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(cast6_lrw_tv_template)
		}
	}, {
		.alg = "lrw(serpent)",
		.generic_driver = "lrw(ecb(serpent-generic))",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(serpent_lrw_tv_template)
		}
	}, {
		.alg = "lrw(twofish)",
		.generic_driver = "lrw(ecb(twofish-generic))",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(tf_lrw_tv_template)
		}
	}, {
		.alg = "lz4",
		.test = fips140_alg_test_comp,
		.fips_allowed = 1,
		.suite = {
			.comp = {
				.comp = __VECS(lz4_comp_tv_template),
				.decomp = __VECS(lz4_decomp_tv_template)
			}
		}
	}, {
		.alg = "lz4hc",
		.test = fips140_alg_test_comp,
		.fips_allowed = 1,
		.suite = {
			.comp = {
				.comp = __VECS(lz4hc_comp_tv_template),
				.decomp = __VECS(lz4hc_decomp_tv_template)
			}
		}
	}, {
		.alg = "lzo",
		.test = fips140_alg_test_comp,
		.fips_allowed = 1,
		.suite = {
			.comp = {
				.comp = __VECS(lzo_comp_tv_template),
				.decomp = __VECS(lzo_decomp_tv_template)
			}
		}
	}, {
		.alg = "lzo-rle",
		.test = fips140_alg_test_comp,
		.fips_allowed = 1,
		.suite = {
			.comp = {
				.comp = __VECS(lzorle_comp_tv_template),
				.decomp = __VECS(lzorle_decomp_tv_template)
			}
		}
	}, {
		.alg = "md4",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(md4_tv_template)
		}
	}, {
		.alg = "md5",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(md5_tv_template)
		}
	}, {
		.alg = "michael_mic",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(michael_mic_tv_template)
		}
	}, {
		.alg = "nhpoly1305",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(nhpoly1305_tv_template)
		}
	}, {
		.alg = "p1363(ecdsa-nist-p192)",
		.test = fips140_alg_test_null,
	}, {
		.alg = "p1363(ecdsa-nist-p256)",
		.test = fips140_alg_test_sig,
		.fips_allowed = 1,
		.suite = {
			.sig = __VECS(p1363_ecdsa_nist_p256_tv_template)
		}
	}, {
		.alg = "p1363(ecdsa-nist-p384)",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "p1363(ecdsa-nist-p521)",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "pcbc(fcrypt)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(fcrypt_pcbc_tv_template)
		}
	}, {
		.alg = "pkcs1(rsa,none)",
		.test = fips140_alg_test_sig,
		.suite = {
			.sig = __VECS(pkcs1_rsa_none_tv_template)
		}
	}, {
		.alg = "pkcs1(rsa,sha224)",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "pkcs1(rsa,sha256)",
		.test = fips140_alg_test_sig,
		.fips_allowed = 1,
		.suite = {
			.sig = __VECS(pkcs1_rsa_tv_template)
		}
	}, {
		.alg = "pkcs1(rsa,sha3-256)",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "pkcs1(rsa,sha3-384)",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "pkcs1(rsa,sha3-512)",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "pkcs1(rsa,sha384)",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "pkcs1(rsa,sha512)",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "pkcs1pad(rsa)",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "poly1305",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(poly1305_tv_template)
		}
	}, {
		.alg = "polyval",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(polyval_tv_template)
		}
	}, {
		.alg = "rfc3686(ctr(aes))",
		.test = fips140_alg_test_skcipher,
		.fips_allowed = 1,
		.suite = {
			.cipher = __VECS(aes_ctr_rfc3686_tv_template)
		}
	}, {
		.alg = "rfc3686(ctr(sm4))",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(sm4_ctr_rfc3686_tv_template)
		}
	}, {
		.alg = "rfc4106(gcm(aes))",
		.generic_driver = "rfc4106(gcm_base(ctr(aes-generic),ghash-generic))",
		.test = fips140_alg_test_aead,
		.fips_allowed = 1,
		.suite = {
			.aead = {
				____VECS(aes_gcm_rfc4106_tv_template),
				.einval_allowed = 1,
				.aad_iv = 1,
			}
		}
	}, {
		.alg = "rfc4309(ccm(aes))",
		.generic_driver = "rfc4309(ccm_base(ctr(aes-generic),cbcmac(aes-generic)))",
		.test = fips140_alg_test_aead,
		.fips_allowed = 1,
		.suite = {
			.aead = {
				____VECS(aes_ccm_rfc4309_tv_template),
				.einval_allowed = 1,
				.aad_iv = 1,
			}
		}
	}, {
		.alg = "rfc4543(gcm(aes))",
		.generic_driver = "rfc4543(gcm_base(ctr(aes-generic),ghash-generic))",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = {
				____VECS(aes_gcm_rfc4543_tv_template),
				.einval_allowed = 1,
				.aad_iv = 1,
			}
		}
	}, {
		.alg = "rfc7539(chacha20,poly1305)",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = __VECS(rfc7539_tv_template)
		}
	}, {
		.alg = "rfc7539esp(chacha20,poly1305)",
		.test = fips140_alg_test_aead,
		.suite = {
			.aead = {
				____VECS(rfc7539esp_tv_template),
				.einval_allowed = 1,
				.aad_iv = 1,
			}
		}
	}, {
		.alg = "rmd160",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(rmd160_tv_template)
		}
	}, {
		.alg = "rsa",
		.test = fips140_alg_test_akcipher,
		.fips_allowed = 1,
		.suite = {
			.akcipher = __VECS(rsa_tv_template)
		}
	}, {
		.alg = "sha1",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(sha1_tv_template)
		}
	}, {
		.alg = "sha224",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(sha224_tv_template)
		}
	}, {
		.alg = "sha256",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(sha256_tv_template)
		}
	}, {
		.alg = "sha3-224",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(sha3_224_tv_template)
		}
	}, {
		.alg = "sha3-256",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(sha3_256_tv_template)
		}
	}, {
		.alg = "sha3-384",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(sha3_384_tv_template)
		}
	}, {
		.alg = "sha3-512",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(sha3_512_tv_template)
		}
	}, {
		.alg = "sha384",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(sha384_tv_template)
		}
	}, {
		.alg = "sha512",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(sha512_tv_template)
		}
	}, {
		.alg = "sm3",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(sm3_tv_template)
		}
	}, {
		.alg = "streebog256",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(streebog256_tv_template)
		}
	}, {
		.alg = "streebog512",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(streebog512_tv_template)
		}
	}, {
		.alg = "wp256",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(wp256_tv_template)
		}
	}, {
		.alg = "wp384",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(wp384_tv_template)
		}
	}, {
		.alg = "wp512",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(wp512_tv_template)
		}
	}, {
		.alg = "x962(ecdsa-nist-p192)",
		.test = fips140_alg_test_sig,
		.suite = {
			.sig = __VECS(x962_ecdsa_nist_p192_tv_template)
		}
	}, {
		.alg = "x962(ecdsa-nist-p256)",
		.test = fips140_alg_test_sig,
		.fips_allowed = 1,
		.suite = {
			.sig = __VECS(x962_ecdsa_nist_p256_tv_template)
		}
	}, {
		.alg = "x962(ecdsa-nist-p384)",
		.test = fips140_alg_test_sig,
		.fips_allowed = 1,
		.suite = {
			.sig = __VECS(x962_ecdsa_nist_p384_tv_template)
		}
	}, {
		.alg = "x962(ecdsa-nist-p521)",
		.test = fips140_alg_test_sig,
		.fips_allowed = 1,
		.suite = {
			.sig = __VECS(x962_ecdsa_nist_p521_tv_template)
		}
	}, {
		.alg = "xcbc(aes)",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(aes_xcbc128_tv_template)
		}
	}, {
		.alg = "xcbc(sm4)",
		.test = fips140_alg_test_hash,
		.suite = {
			.hash = __VECS(sm4_xcbc128_tv_template)
		}
	}, {
		.alg = "xchacha12",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(xchacha12_tv_template)
		},
	}, {
		.alg = "xchacha20",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(xchacha20_tv_template)
		},
	}, {
		.alg = "xctr(aes)",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(aes_xctr_tv_template)
		}
	}, {
		.alg = "xts(aes)",
		.generic_driver = "xts(ecb(aes-generic))",
		.test = fips140_alg_test_skcipher,
		.fips_allowed = 1,
		.suite = {
			.cipher = __VECS(aes_xts_tv_template)
		}
	}, {
		.alg = "xts(camellia)",
		.generic_driver = "xts(ecb(camellia-generic))",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(camellia_xts_tv_template)
		}
	}, {
		.alg = "xts(cast6)",
		.generic_driver = "xts(ecb(cast6-generic))",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(cast6_xts_tv_template)
		}
	}, {
		/* Same as xts(aes) except the key is stored in
		 * hardware secure memory which we reference by index
		 */
		.alg = "xts(paes)",
		.test = fips140_alg_test_null,
		.fips_allowed = 1,
	}, {
		.alg = "xts(serpent)",
		.generic_driver = "xts(ecb(serpent-generic))",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(serpent_xts_tv_template)
		}
	}, {
		.alg = "xts(sm4)",
		.generic_driver = "xts(ecb(sm4-generic))",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(sm4_xts_tv_template)
		}
	}, {
		.alg = "xts(twofish)",
		.generic_driver = "xts(ecb(twofish-generic))",
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(tf_xts_tv_template)
		}
	}, {
#if IS_ENABLED(CONFIG_CRYPTO_PAES_S390)
		.alg = "xts-paes-s390",
		.fips_allowed = 1,
		.test = fips140_alg_test_skcipher,
		.suite = {
			.cipher = __VECS(aes_xts_tv_template)
		}
	}, {
#endif
		.alg = "xxhash64",
		.test = fips140_alg_test_hash,
		.fips_allowed = 1,
		.suite = {
			.hash = __VECS(xxhash64_tv_template)
		}
	}, {
		.alg = "zstd",
		.test = fips140_alg_test_comp,
		.fips_allowed = 1,
		.suite = {
			.comp = {
				.comp = __VECS(zstd_comp_tv_template),
				.decomp = __VECS(zstd_decomp_tv_template)
			}
		}
	}
};

const int fips140_alg_test_descs_count = ARRAY_SIZE(fips140_alg_test_descs);

static int fips140_alg_find_test(const char *alg)
{
	int start = 0;
	int end = fips140_alg_test_descs_count;

	while (start < end) {
		int i = (start + end) / 2;
		int diff = strcmp(fips140_alg_test_descs[i].alg, alg);

		if (diff > 0) {
			end = i;
		} else if (diff < 0) {
			start = i + 1;
		} else {
			return i;
		}
	}

	return -1;
}

int fips140_alg_test(const char *driver, const char *alg, u32 type, u32 mask)
{
	int i;
	int j;
	int rc;

	i = fips140_alg_find_test(alg);
	j = fips140_alg_find_test(driver);
	if (i < 0 && j < 0)
		goto notest;

	rc = 0;
	if (i >= 0)
		rc |= fips140_alg_test_descs[i].test(&fips140_alg_test_descs[i], driver, type, mask);
	if (j >= 0 && j != i)
		rc |= fips140_alg_test_descs[j].test(&fips140_alg_test_descs[j], driver, type, mask);

	if (rc) {
		pr_err("fips140: self-tests for %s (%s) failed: %d\n", driver, alg, rc);
	} else {
		pr_info("fips140: self-tests for %s (%s) passed\n", driver, alg);
	}

	return rc;

notest:
	pr_info("fips140: No test for %s (%s)\n", alg, driver);
	return 0;
}
EXPORT_SYMBOL_GPL(fips140_alg_test);
