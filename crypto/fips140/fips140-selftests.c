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

/* Forward declarations to avoid including the full testsuites header */
struct fips140_alg_test_desc {
	const char *alg;
	const char *generic_driver;
	int (*test)(const struct fips140_alg_test_desc *desc, const char *driver,
		    u32 type, u32 mask);
	int fips_allowed;
	/* We don't need the union for our purposes */
};

/* External declarations from fips140-testsuites.c */
extern const struct fips140_alg_test_desc fips140_alg_test_descs[];
extern const int fips140_alg_test_descs_count;

/* Use the binary search function from testsuites.c */
extern int fips140_alg_find_test(const char *alg);

/* External declarations from fips140-alg-registration.c */
extern void fips140_get_registered_algorithms(struct list_head **algs_list, struct mutex **list_mutex);

/* Structure for registered algorithms (from fips140-alg-registration.c) */
struct fips140_registered_alg {
	struct list_head list;
	char *cra_name;
	char *cra_driver_name;
	u32 cra_flags;
	u32 cra_type;
	int cra_priority;
	bool tested;
	bool test_passed;
};

/* 
 * This file runs self-tests for all registered FIPS 140 algorithms
 * using the test descriptors from fips140-testsuites.c
 */



bool __init fips140_run_selftests(void)
{
	struct list_head *algs_list;
	struct mutex *list_mutex;
	struct fips140_registered_alg *reg_alg;
	bool all_passed = true;
	int tests_run = 0;

	pr_info("running self-tests for registered algorithms\n");

	// Get access to the registered algorithms list
	fips140_get_registered_algorithms(&algs_list, &list_mutex);

	mutex_lock(list_mutex);
	list_for_each_entry(reg_alg, algs_list, list) {
		const struct fips140_alg_test_desc *test_desc = NULL;
		int err;

		// Find matching test descriptor (following testmgr.c logic)
		int alg_idx = fips140_alg_find_test(reg_alg->cra_name);
		int driver_idx = fips140_alg_find_test(reg_alg->cra_driver_name);
		
		// Prefer driver-specific test over generic algorithm test
		if (driver_idx >= 0)
			test_desc = &fips140_alg_test_descs[driver_idx];
		else if (alg_idx >= 0)
			test_desc = &fips140_alg_test_descs[alg_idx];

		if (!test_desc || !test_desc->test) {
			pr_info("self-test: no test found for %s (%s), skipping\n",
				reg_alg->cra_name, reg_alg->cra_driver_name);
			continue;
		}

		pr_info("self-test: running test for %s (%s)\n",
			reg_alg->cra_name, reg_alg->cra_driver_name);

		err = test_desc->test(test_desc, reg_alg->cra_driver_name,
				      reg_alg->cra_type, 0);
		
		reg_alg->tested = true;
		if (err) {
			pr_err("self-test: %s (%s) failed (err=%d)\n",
			       reg_alg->cra_name, reg_alg->cra_driver_name, err);
			reg_alg->test_passed = false;
			all_passed = false;
		} else {
			reg_alg->test_passed = true;
		}
		tests_run++;
	}
	mutex_unlock(list_mutex);

	if (tests_run == 0) {
		pr_warn("no self-tests were run\n");
		return false;
	}

	if (all_passed)
		pr_info("all %d self-tests passed\n", tests_run);
	else
		pr_err("one or more self-tests failed\n");

	return all_passed;
}
