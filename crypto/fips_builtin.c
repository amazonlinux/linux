#include <linux/export.h>
#include <linux/fips.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string_choices.h>

int fips_enabled;
EXPORT_SYMBOL_GPL(fips_enabled);

/* Process kernel command-line parameter at boot time. fips=0 or fips=1 */
static int fips_enable(char *str)
{
	fips_enabled = !!simple_strtol(str, NULL, 0);
	pr_info("fips mode: %s\n", str_enabled_disabled(fips_enabled));
	return 1;
}

__setup("fips=", fips_enable);