#ifndef _CRYPTO_FIPS140_REDIRECT_H
#define _CRYPTO_FIPS140_REDIRECT_H

#define CRYPTO_VAR_NAME(name) __crypto_##name##_ptr

#define __CAT(a,b) a##b
#define _CAT(a,b)  __CAT(a,b)

#define __IF_1(...) __VA_ARGS__
#define __IF_0(...)
#define __IFNOT_1(...)
#define __IFNOT_0(...) __VA_ARGS__

/* Emit __VA_ARGS__ only if cfg is built into vmlinux (=y) */
#define IF_BUILTIN(cfg, ...)     _CAT(__IF_,    IS_BUILTIN(cfg))(__VA_ARGS__)
/* Emit __VA_ARGS__ only if cfg is NOT built in (i.e., =m or unset) */
#define IF_NOT_BUILTIN(cfg, ...) _CAT(__IFNOT_, IS_BUILTIN(cfg))(__VA_ARGS__)

#if !defined(CONFIG_CRYPTO_FIPS140_EXTMOD)

/*
 * These are the definitions that get used when no standalone FIPS module
 * is used: we simply forward everything to normal variable declaration.
 */

#define DECLARE_CRYPTO_VAR(cfg, name, var_type, ...) \
	extern var_type name __VA_ARGS__;
#else

struct crypto_fn_key {
	void **ptr;
	void *func;
};

struct crypto_var_key {
	void **ptr;
	void *var;
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

/*
 *  - If cfg is built-in (=y): declare the address placeholder
 *  - Else (cfg =m or unset): only declare the original <name>().
 */

#define DECLARE_CRYPTO_VAR(cfg, name, var_type, ...) \
	IF_BUILTIN(cfg, \
		extern void *CRYPTO_VAR_NAME(name); \
	) \
	IF_NOT_BUILTIN(cfg, \
		extern var_type name __VA_ARGS__; \
	)

#define DEFINE_CRYPTO_VAR_STUB(name) \
	void* CRYPTO_VAR_NAME(name) = NULL;\
	EXPORT_SYMBOL(CRYPTO_VAR_NAME(name));
	
#else /* defined(FIPS_MODULE) */

#define DECLARE_CRYPTO_VAR(cfg, name, var_type, ...)               \
	IF_BUILTIN(cfg,                                             \
		extern var_type name __VA_ARGS__;                   \
		extern void *CRYPTO_VAR_NAME(name);                  \
	)                                                            \
	IF_NOT_BUILTIN(cfg,                                          \
		extern var_type name __VA_ARGS__;                   \
	)

#define DEFINE_CRYPTO_VAR_STUB(name) \
	static struct crypto_var_key __crypto_##name##_var_key \
		__used \
		__section("__crypto_var_keys") \
		__aligned(__alignof__(struct crypto_var_key)) = \
	{ \
		.ptr = &CRYPTO_VAR_NAME(name), \
		.var = (void*)&name, \
	};

#endif /* defined(FIPS_MODULE) */
#endif /* defined(CONFIG_CRYPTO_FIPS140_EXTMOD) */

#endif /* !_CRYPTO_FIPS140_REDIRECT_H */
