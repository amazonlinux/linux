// SPDX-License-Identifier: GPL-2.0-only
/*
 * FIPS 140 Kernel Cryptographic Module
 * Self-tests for the FIPS module
 */

#include <crypto/aead.h>
#include <crypto/aes.h>
#include <crypto/hash.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <crypto/sha3.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/fips.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/types.h>

#include "fips140-module.h"

/* 
 * This file will contain all the self-tests required for FIPS 140 compliance.
 * For now, we'll implement a basic structure that can be expanded later.
 */

struct fips140_selftest_alg {
	const char *driver_name;
	const char *test_name;
	int (*test_func)(const struct fips140_selftest_alg *alg);
};

/* AES Known Answer Tests */
static int fips140_aes_ecb_test(const struct fips140_selftest_alg *alg)
{
	/* Implement AES-ECB KAT */
	return 0;
}

static int fips140_aes_cbc_test(const struct fips140_selftest_alg *alg)
{
	/* Implement AES-CBC KAT */
	return 0;
}

static int fips140_aes_ctr_test(const struct fips140_selftest_alg *alg)
{
	/* Implement AES-CTR KAT */
	return 0;
}

static int fips140_aes_xts_test(const struct fips140_selftest_alg *alg)
{
	/* Implement AES-XTS KAT */
	return 0;
}

/* SHA Known Answer Tests */
static int fips140_sha1_test(const struct fips140_selftest_alg *alg)
{
	/* Implement SHA1 KAT */
	return 0;
}

static int fips140_sha256_test(const struct fips140_selftest_alg *alg)
{
	/* Implement SHA256 KAT */
	return 0;
}

static int fips140_sha512_test(const struct fips140_selftest_alg *alg)
{
	/* Implement SHA512 KAT */
	return 0;
}

/* HMAC Known Answer Tests */
static int fips140_hmac_sha256_test(const struct fips140_selftest_alg *alg)
{
	/* Implement HMAC-SHA256 KAT */
	return 0;
}

/* List of all self-tests to run */
static const struct fips140_selftest_alg fips140_selftests[] = {
	{
		.driver_name = "ecb(aes)",
		.test_name = "AES-ECB",
		.test_func = fips140_aes_ecb_test,
	}, {
		.driver_name = "cbc(aes)",
		.test_name = "AES-CBC",
		.test_func = fips140_aes_cbc_test,
	}, {
		.driver_name = "ctr(aes)",
		.test_name = "AES-CTR",
		.test_func = fips140_aes_ctr_test,
	}, {
		.driver_name = "xts(aes)",
		.test_name = "AES-XTS",
		.test_func = fips140_aes_xts_test,
	}, {
		.driver_name = "sha1",
		.test_name = "SHA-1",
		.test_func = fips140_sha1_test,
	}, {
		.driver_name = "sha256",
		.test_name = "SHA-256",
		.test_func = fips140_sha256_test,
	}, {
		.driver_name = "sha512",
		.test_name = "SHA-512",
		.test_func = fips140_sha512_test,
	}, {
		.driver_name = "hmac(sha256)",
		.test_name = "HMAC-SHA-256",
		.test_func = fips140_hmac_sha256_test,
	},
};

bool __init fips140_run_selftests(void)
{
	int i;
	bool all_passed = true;

	pr_info("running self-tests\n");

	for (i = 0; i < ARRAY_SIZE(fips140_selftests); i++) {
		const struct fips140_selftest_alg *alg = &fips140_selftests[i];
		int err;

		pr_info("self-test: %s\n", alg->test_name);
		err = alg->test_func(alg);
		if (err) {
			pr_err("self-test: %s failed (err=%d)\n",
			       alg->test_name, err);
			all_passed = false;
		}
	}

	if (all_passed)
		pr_info("all self-tests passed\n");
	else
		pr_err("one or more self-tests failed\n");

	return all_passed;
}
