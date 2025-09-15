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

/* Consolidated version of different DECLARE_CRYPTO_API versions,
   within FIPS module, API remains the same, only declare static 
   call key */
#define DECLARE_CRYPTO_API(name, ret_type, args_decl, args_call)	\
	ret_type name args_decl;					\
	DECLARE_STATIC_CALL(crypto_##name##_key, name);		

/*
 * These are the definitions that get used for the main kernel.
 *
 * In this case, initialize crypto static call key with original name
 */

#define DEFINE_CRYPTO_API_STUB(name) \
	static struct crypto_api_key __##name##_key \
		__used \
		__section("__crypto_api_keys") \
		__aligned(__alignof__(struct crypto_api_key)) = \
	{ \
		.key = &STATIC_CALL_KEY(crypto_##name##_key), \
		.tramp = STATIC_CALL_TRAMP_ADDR(crypto_##name##_key), \
		.func = &name, \
	};

#define crypto_module_init(fn) \
	static initcall_t __used __section(".fips_initcall6") \
		__fips_##fn = fn;
#define crypto_module_exit(fn) \
		static unsigned long __used __section(".fips_exitcall") \
		__fips_##fn = (unsigned long) &fn;
#define crypto_arch_initcall(fn) \
	static initcall_t __used __section(".fips_initcall3") \
		__fips_##fn = fn;
#define crypto_arch_exitcall(fn) \
		static unsigned long __used __section(".fips_exitcall") \
		__fips_##fn = (unsigned long) &fn;
#define crypto_subsys_initcall(fn) \
	static initcall_t __used __section(".fips_initcall4") \
		__fips_##fn = fn;
#define crypto_subsys_exitcall(fn) \
		static unsigned long __used __section(".fips_exitcall") \
		__fips_##fn = (unsigned long) &fn;
#define crypto_late_initcall(fn) \
	static initcall_t __used __section(".fips_initcall7") \
		__fips_##fn = fn;
#define crypto_late_exitcall(fn) \
		static unsigned long __used __section(".fips_exitcall") \
		__fips_##fn = (unsigned long) &fn;

#endif /* defined(FIPS_MODULE) */
#endif /* defined(CONFIG_CRYPTO_FIPS140_EXTMOD) */

#endif /* !_CRYPTO_API_H */
