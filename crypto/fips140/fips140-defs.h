/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * This file is automatically included by all files built into fips140.ko, via
 * the "-include" compiler flag.
 */


/*
 * Disable symbol exports by default.  fips140.ko includes various files that
 * use EXPORT_SYMBOL*(), but it's unwanted to export any symbols from fips140.ko
 * except where explicitly needed for FIPS certification reasons.
 */
#define __DISABLE_EXPORTS

/*
 * Override module_init to place functions in our custom .fips_initcall6 section
 * This ensures all crypto module_init functions go to the same place
 */
#define module_init(initfn) \
	static initcall_t __initcall_##initfn __used \
	__attribute__((__section__(".fips_initcall6"))) = initfn

/*
 * Redirect all calls to algorithm registration functions to the wrapper
 * functions defined within the module.
 */
#define crypto_register_alg		fips140_crypto_register_alg
#define crypto_register_algs		fips140_crypto_register_algs
#define crypto_register_template	fips140_crypto_register_template
#define crypto_register_templates	fips140_crypto_register_templates
#define crypto_register_instance	fips140_crypto_register_instance

/*
 * Redirections for unexported kernel functions (not crypto API)
 * These functions are not exported by the main kernel but are needed
 * by crypto algorithms. We redirect them to fips140_ prefixed versions
 * that are implemented in crypto/fips140/builtin/ and compiled into
 * the main kernel.
 */
#define restrict_link_by_builtin_trusted fips140_restrict_link_by_builtin_trusted
#define __SCK__might_resched fips140___SCK__might_resched
#define __SCK__preempt_schedule fips140___SCK__preempt_schedule

/* RAID6 symbol redirections */
#if defined(CONFIG_RAID6_PQ) && !IS_MODULE(CONFIG_RAID6_PQ)
#define raid6_2data_recov fips140_raid6_2data_recov
#define raid6_datap_recov fips140_raid6_datap_recov
#define raid6_call (*fips140_raid6_call)
#define raid6_gfexp fips140_raid6_gfexp
#define raid6_gfmul fips140_raid6_gfmul
#define raid6_gfinv fips140_raid6_gfinv
#define raid6_gfexi fips140_raid6_gfexi
#define raid6_empty_zero_page (*((const void **)fips140_raid6_empty_zero_page))
#endif

/* ZSTD symbol redirections */
#if defined(CONFIG_ZSTD_COMPRESS) && !IS_MODULE(CONFIG_ZSTD_COMPRESS)
#define zstd_cctx_workspace_bound fips140_zstd_cctx_workspace_bound
#define zstd_init_cctx fips140_zstd_init_cctx
#define zstd_compress_cctx fips140_zstd_compress_cctx
#define zstd_get_params fips140_zstd_get_params
#endif

/* LZ4 symbol redirections - only when NOT built as modules
 * When =y (built-in), symbols are available in kernel, use wrappers
 * When =m (module), symbols not available, include source directly
 */
#if defined(CONFIG_LZ4_COMPRESS) && !IS_MODULE(CONFIG_LZ4_COMPRESS)
#define LZ4_compress_default fips140_LZ4_compress_default
#define LZ4_compress_HC fips140_LZ4_compress_HC
#endif

#if defined(CONFIG_LZ4_DECOMPRESS) && !IS_MODULE(CONFIG_LZ4_DECOMPRESS)
#define LZ4_decompress_safe fips140_LZ4_decompress_safe
#endif

/* Poly1305 core function redirections - only when built-in */
#if defined(CONFIG_CRYPTO_LIB_POLY1305_GENERIC) && !IS_MODULE(CONFIG_CRYPTO_LIB_POLY1305_GENERIC)
#define poly1305_core_setkey fips140_poly1305_core_setkey
#define poly1305_core_blocks fips140_poly1305_core_blocks
#define poly1305_core_emit fips140_poly1305_core_emit
#endif
