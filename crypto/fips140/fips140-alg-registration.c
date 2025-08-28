// SPDX-License-Identifier: GPL-2.0-only
/*
 * FIPS 140 Algorithm Registration Tracking
 *
 * This file tracks all algorithms registered by the FIPS module
 * so that self-tests can be run only on actually registered algorithms.
 */

/*
 * This file is the one place in fips140.ko that needs to call the kernel's real
 * algorithm registration functions, so #undefine all the macros from
 * fips140-defs.h so that the "fips140_" prefix doesn't automatically get added.
 */
#undef crypto_register_alg
#undef crypto_register_algs
#undef crypto_register_template
#undef crypto_register_templates
#undef crypto_register_instance


#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <crypto/algapi.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/rng.h>
#include <crypto/internal/skcipher.h>

#include "fips140-module.h"

// Structure to track registered algorithms
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

// Global list of registered algorithms
static LIST_HEAD(fips140_registered_algs);
static DEFINE_MUTEX(fips140_registered_algs_mutex);

// Statistics
static int fips140_total_registered = 0;
static int fips140_total_tested = 0;
static int fips140_total_passed = 0;

/**
 * fips140_record_algorithm - Record an algorithm registration
 * @alg: The crypto algorithm that was registered
 * 
 * This function is called whenever a FIPS algorithm is successfully registered
 * to keep track of what needs to be tested.
 */
static int fips140_record_algorithm(struct crypto_alg *alg)
{
    struct fips140_registered_alg *reg_alg;
    u32 type;
    
    if (!alg) {
        pr_err("fips140: Cannot record NULL algorithm\n");
        return -EINVAL;
    }
    
    reg_alg = kzalloc(sizeof(*reg_alg), GFP_KERNEL);
    if (!reg_alg)
        return -ENOMEM;
    
    // Copy algorithm information
    reg_alg->cra_name = kstrdup(alg->cra_name, GFP_KERNEL);
    reg_alg->cra_driver_name = kstrdup(alg->cra_driver_name, GFP_KERNEL);
    if (!reg_alg->cra_name || !reg_alg->cra_driver_name) {
        kfree(reg_alg->cra_name);
        kfree(reg_alg->cra_driver_name);
        kfree(reg_alg);
        return -ENOMEM;
    }
    
    reg_alg->cra_flags = alg->cra_flags;
    reg_alg->cra_priority = alg->cra_priority;
    reg_alg->tested = false;
    reg_alg->test_passed = false;
    
    // Determine algorithm type
    type = alg->cra_flags & CRYPTO_ALG_TYPE_MASK;
    reg_alg->cra_type = type;
    
    // Add to the list
    mutex_lock(&fips140_registered_algs_mutex);
    list_add_tail(&reg_alg->list, &fips140_registered_algs);
    fips140_total_registered++;
    mutex_unlock(&fips140_registered_algs_mutex);
    
    pr_info("fips140: Recorded algorithm: %s (%s), type=0x%x, priority=%d\n", 
            alg->cra_name, alg->cra_driver_name, type, alg->cra_priority);
    
    return 0;
}

/**
 * fips140_get_algorithm_type_name - Get human-readable type name
 * @type: Algorithm type flags
 */
static const char *fips140_get_algorithm_type_name(u32 type)
{
    switch (type) {
    case CRYPTO_ALG_TYPE_CIPHER:
        return "cipher";
    case CRYPTO_ALG_TYPE_AEAD:
        return "aead";
    case CRYPTO_ALG_TYPE_SKCIPHER:
        return "skcipher";
    case CRYPTO_ALG_TYPE_AKCIPHER:
        return "akcipher";
    case CRYPTO_ALG_TYPE_SIG:
        return "sig";
    case CRYPTO_ALG_TYPE_KPP:
        return "kpp";
    case CRYPTO_ALG_TYPE_ACOMPRESS:
        return "acompress";
    case CRYPTO_ALG_TYPE_SCOMPRESS:
        return "scompress";
    case CRYPTO_ALG_TYPE_RNG:
        return "rng";
    case CRYPTO_ALG_TYPE_SHASH:  // Note: HASH and SHASH have same value (0xe)
        return "hash/shash";
    case CRYPTO_ALG_TYPE_AHASH:
        return "ahash";
    default:
        return "unknown";
    }
}

/**
 * fips140_print_registered_algorithms - Print all registered algorithms
 */
void fips140_print_registered_algorithms(void)
{
    struct fips140_registered_alg *reg_alg;
    int count = 0;
    
    pr_info("=== FIPS 140 Registered Algorithms ===\n");
    
    mutex_lock(&fips140_registered_algs_mutex);
    list_for_each_entry(reg_alg, &fips140_registered_algs, list) {
        count++;
        pr_info("Algorithm #%d:\n", count);
        pr_info("  Name: %s\n", reg_alg->cra_name);
        pr_info("  Driver: %s\n", reg_alg->cra_driver_name);
        pr_info("  Type: %s (0x%x)\n", 
                fips140_get_algorithm_type_name(reg_alg->cra_type), 
                reg_alg->cra_type);
        pr_info("  Priority: %d\n", reg_alg->cra_priority);
        pr_info("  Flags: 0x%x\n", reg_alg->cra_flags);
        pr_info("  Tested: %s\n", reg_alg->tested ? "Yes" : "No");
        if (reg_alg->tested) {
            pr_info("  Result: %s\n", reg_alg->test_passed ? "PASSED" : "FAILED");
        }
        pr_info("\n");
    }
    mutex_unlock(&fips140_registered_algs_mutex);
    
    pr_info("=== Total: %d algorithms registered ===\n", count);
}
EXPORT_SYMBOL_GPL(fips140_print_registered_algorithms);

/**
 * fips140_get_registered_algorithms - Get the list of registered algorithms
 * @algs_list: Pointer to receive the list head
 * 
 * Returns the list of registered algorithms for testing.
 * Caller must hold the mutex while iterating.
 */
void fips140_get_registered_algorithms(struct list_head **algs_list, 
                                       struct mutex **list_mutex)
{
    *algs_list = &fips140_registered_algs;
    *list_mutex = &fips140_registered_algs_mutex;
}
EXPORT_SYMBOL_GPL(fips140_get_registered_algorithms);

/**
 * fips140_mark_algorithm_tested - Mark an algorithm as tested
 * @cra_name: Algorithm name
 * @cra_driver_name: Driver name
 * @passed: Whether the test passed
 */
void fips140_mark_algorithm_tested(const char *cra_name, 
                                   const char *cra_driver_name, 
                                   bool passed)
{
    struct fips140_registered_alg *reg_alg;
    bool found = false;
    
    if (!cra_name || !cra_driver_name) {
        pr_err("fips140: Invalid algorithm names for test marking\n");
        return;
    }
    
    mutex_lock(&fips140_registered_algs_mutex);
    list_for_each_entry(reg_alg, &fips140_registered_algs, list) {
        if (strcmp(reg_alg->cra_name, cra_name) == 0 &&
            strcmp(reg_alg->cra_driver_name, cra_driver_name) == 0) {
            
            if (!reg_alg->tested) {
                fips140_total_tested++;
                if (passed) {
                    fips140_total_passed++;
                }
            } else {
                // Update existing result
                if (reg_alg->test_passed && !passed) {
                    fips140_total_passed--;
                } else if (!reg_alg->test_passed && passed) {
                    fips140_total_passed++;
                }
            }
            
            reg_alg->tested = true;
            reg_alg->test_passed = passed;
            found = true;
            
            pr_info("fips140: Marked %s (%s) as %s\n", 
                    cra_name, cra_driver_name, passed ? "PASSED" : "FAILED");
            break;
        }
    }
    mutex_unlock(&fips140_registered_algs_mutex);
    
    if (!found) {
        pr_warn("fips140: Algorithm %s (%s) not found in registered list\n",
                cra_name, cra_driver_name);
    }
}
EXPORT_SYMBOL_GPL(fips140_mark_algorithm_tested);

/**
 * fips140_get_test_statistics - Get testing statistics
 * @total_registered: Total algorithms registered
 * @total_tested: Total algorithms tested
 * @total_passed: Total algorithms that passed tests
 */
void fips140_get_test_statistics(int *total_registered, int *total_tested, 
                                 int *total_passed)
{
    mutex_lock(&fips140_registered_algs_mutex);
    if (total_registered)
        *total_registered = fips140_total_registered;
    if (total_tested)
        *total_tested = fips140_total_tested;
    if (total_passed)
        *total_passed = fips140_total_passed;
    mutex_unlock(&fips140_registered_algs_mutex);
}
EXPORT_SYMBOL_GPL(fips140_get_test_statistics);

/**
 * fips140_check_all_algorithms_tested - Check if all algorithms were tested
 * 
 * Returns true if all registered algorithms have been tested and passed.
 */
bool fips140_check_all_algorithms_tested(void)
{
    struct fips140_registered_alg *reg_alg;
    bool all_tested = true;
    int untested_count = 0;
    int failed_count = 0;
    
    mutex_lock(&fips140_registered_algs_mutex);
    list_for_each_entry(reg_alg, &fips140_registered_algs, list) {
        if (!reg_alg->tested) {
            pr_warn("fips140: Algorithm %s (%s) was not tested\n",
                    reg_alg->cra_name, reg_alg->cra_driver_name);
            untested_count++;
            all_tested = false;
        } else if (!reg_alg->test_passed) {
            pr_err("fips140: Algorithm %s (%s) failed testing\n",
                   reg_alg->cra_name, reg_alg->cra_driver_name);
            failed_count++;
            all_tested = false;
        }
    }
    mutex_unlock(&fips140_registered_algs_mutex);
    
    if (untested_count > 0) {
        pr_err("fips140: %d algorithms were not tested\n", untested_count);
    }
    if (failed_count > 0) {
        pr_err("fips140: %d algorithms failed testing\n", failed_count);
    }
    
    return all_tested;
}
EXPORT_SYMBOL_GPL(fips140_check_all_algorithms_tested);

/*
 * Registration wrapper functions
 * These hook into your existing registration functions to record algorithms
 */

/**
 * fips140_crypto_register_alg - Register and record a crypto algorithm
 */
int fips140_crypto_register_alg(struct crypto_alg *alg)
{
    int err;
    // Call the original registration function from your existing code
    err = crypto_register_alg(alg);
    if (err) {
        pr_err("fips140: Failed to register algorithm %s: %d\n", 
               alg->cra_name, err);
        return err;
    }
    
    // Record the algorithm for testing
    err = fips140_record_algorithm(alg);
    if (err) {
        pr_warn("fips140: Failed to record algorithm %s: %d\n", 
                alg->cra_name, err);
        // Don't fail registration just because recording failed
    }
    
    return 0;
}


int fips140_crypto_register_algs(struct crypto_alg *algs, int count)
{
    int err, i;
    
    err = crypto_register_algs(algs, count);
    if (err)
        return err;
    
    for (i = 0; i < count; i++) {
        // Record the algorithm for testing
        err = fips140_record_algorithm(&algs[i]);
        if (err) {
            pr_warn("fips140: Failed to record algorithm %s: %d\n", 
                    algs[i].cra_name, err);
            // Don't fail registration just because recording failed
        }
    }
    
    return 0;
}
EXPORT_SYMBOL_GPL(fips140_crypto_register_algs);

int fips140_crypto_register_template(struct crypto_template *tmpl)
{
    return crypto_register_template(tmpl);
}
EXPORT_SYMBOL_GPL(fips140_crypto_register_template);

int fips140_crypto_register_templates(struct crypto_template *tmpls, int count)
{
    return crypto_register_templates(tmpls, count);
}
EXPORT_SYMBOL_GPL(fips140_crypto_register_templates);

int fips140_crypto_register_instance(struct crypto_template *tmpl, struct crypto_instance *inst)
{
    int err;
    
    err = crypto_register_instance(tmpl, inst);
    if (err)
        return err;
    
    // Record the algorithm for testing
    err = fips140_record_algorithm(&inst->alg);
    if (err) {
        pr_warn("fips140: Failed to record algorithm %s: %d\n", 
                inst->alg.cra_name, err);
        // Don't fail registration just because recording failed
    }
    
    return 0;
}
EXPORT_SYMBOL_GPL(fips140_crypto_register_instance);


/**
 * fips140_cleanup_registered_algorithms - Clean up the registration tracking
 * 
 * This should be called during module cleanup.
 */
void fips140_cleanup_registered_algorithms(void)
{
    struct fips140_registered_alg *reg_alg, *tmp;
    
    mutex_lock(&fips140_registered_algs_mutex);
    list_for_each_entry_safe(reg_alg, tmp, &fips140_registered_algs, list) {
        list_del(&reg_alg->list);
        kfree(reg_alg->cra_name);
        kfree(reg_alg->cra_driver_name);
        kfree(reg_alg);
    }
    
    fips140_total_registered = 0;
    fips140_total_tested = 0;
    fips140_total_passed = 0;
    mutex_unlock(&fips140_registered_algs_mutex);
    
    pr_info("fips140: Cleaned up algorithm registration tracking\n");
}
EXPORT_SYMBOL_GPL(fips140_cleanup_registered_algorithms);
