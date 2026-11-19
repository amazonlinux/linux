// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * __crypto_stdrng_get_bytes(), which 7.1 added to crypto/rng.c.
 *
 * crypto/rng.c is inside the certified FIPS boundary and is frozen at a revision
 * that predates this entry point, so it cannot carry it.  The body below is
 * upstream 7.1's verbatim: it is built into vmlinux and calls the default-RNG
 * helpers that the frozen crypto/rng.c defines and exports, so the random bytes
 * still come from the module's DRBG.  crypto_default_rng resolves through the
 * pluggable-variable indirection in <crypto/rng.h>.
 *
 * Callers reach this through the crypto_stdrng_get_bytes() static inline in
 * <crypto/rng.h>, which only uses it when fips_enabled is set.
 */

#include <crypto/rng.h>
#include <linux/export.h>

int __crypto_stdrng_get_bytes(void *buf, unsigned int len)
{
	int err;

	err = crypto_get_default_rng();
	if (err)
		return err;

	err = crypto_rng_get_bytes(crypto_default_rng, buf, len);
	crypto_put_default_rng();
	return err;
}
EXPORT_SYMBOL_GPL(__crypto_stdrng_get_bytes);
