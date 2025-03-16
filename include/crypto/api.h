#ifndef _CRYPTO_API_H
#define _CRYPTO_API_H

#include <linux/static_call.h>

#if !defined(CONFIG_CRYPTO_FIPS140_EXTMOD)

/*
 * These are the definitions that get used when no standalone FIPS module
 * is used: we simply forward everything to normal functions and function
 * calls.
 */

#define DECLARE_CRYPTO_API(name, ret_type, args_decl, args_call) \
	ret_type name args_decl;

#define crypto_module_init(fn) module_init(fn)
#define crypto_module_exit(fn) module_exit(fn)

#define crypto_arch_initcall(fn)	arch_initcall(fn)
#define crypto_subsys_initcall(fn)	subsys_initcall(fn)
#define crypto_late_initcall(fn)	late_initcall(fn)

#else

struct crypto_api_key {
	struct static_call_key *key;
	void *tramp;
	void *func;
};

#ifndef FIPS_MODULE

/*
 * These are the definitions that get used for vmlinux and in-tree
 * kernel modules.
 *
 * In this case, all references to the kernel crypto API functions will
 * be replaced by wrappers that perform a call using the kernel's static_call
 * functionality.
 */

/* Consolidated version of different DECLARE_CRYPTO_API versions */
#define DECLARE_CRYPTO_API(name, ret_type, args_decl, args_call)	\
	ret_type nonfips_##name args_decl;				\
	DECLARE_STATIC_CALL(crypto_##name##_key, nonfips_##name);	\
	static inline ret_type name args_decl				\
	{								\
		return static_call(crypto_##name##_key) args_call;	\
	}

#define DEFINE_CRYPTO_API_STUB(name) \
	DEFINE_STATIC_CALL_NULL(crypto_##name##_key, name); \
	EXPORT_STATIC_CALL(crypto_##name##_key)

#define crypto_module_init(fn) module_init(fn)
#define crypto_module_exit(fn) module_exit(fn)

#define crypto_arch_initcall(fn)	arch_initcall(fn)
#define crypto_subsys_initcall(fn)	subsys_initcall(fn)
#define crypto_late_initcall(fn)	late_initcall(fn)

#else /* defined(FIPS_MODULE) */

/*
 * These are the definitions that get used for the FIPS module and
 * its kernel modules.
 *
 * In this case, all crypto API functions resolve directly to their
 * implementations, since they are all part of the FIPS module.
 *
 * We still need to declare the static call keys so we can update
 * them when the FIPS modules have all been loaded.
 */

#endif /* defined(FIPS_MODULE) */
#endif /* defined(CONFIG_CRYPTO_FIPS140_EXTMOD) */

#endif /* !_CRYPTO_API_H */
