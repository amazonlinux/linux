/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FIPS_H
#define _FIPS_H

#ifdef CONFIG_CRYPTO_FIPS
#include <crypto/fips140-redirect.h>
extern int fips_enabled;
DECLARE_CRYPTO_VAR(CONFIG_CRYPTO_FIPS, fips_fail_notif_chain, struct atomic_notifier_head, );

#if defined(CONFIG_CRYPTO_FIPS140_EXTMOD) && !defined(FIPS_MODULE) && IS_BUILTIN(CONFIG_CRYPTO_FIPS)
#define fips_fail_notif_chain (*((struct atomic_notifier_head*)CRYPTO_VAR_NAME(fips_fail_notif_chain)))
#endif

void fips_fail_notify(void);

#else
#define fips_enabled 0

static inline void fips_fail_notify(void) {}

#endif

#endif
