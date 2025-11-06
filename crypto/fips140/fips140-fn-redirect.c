// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <crypto/fips140-fn-redirect.h>
#include ".fips140-fn-redirect.h"

void __fips140_fn_not_redirected(void)
{
	panic("FIPS140: redirected function called before fips140.ko loaded!\n");
}
 