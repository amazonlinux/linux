# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the FIPS 140 kernel module
#

FIPS140_CFLAGS := -DBUILD_FIPS140_KO -include $(srctree)/crypto/fips140/fips140-defs.h

# Compile an extra copy of various crypto algorithms into the fips140 module
crypto-fips-objs := drbg.o ecb.o cbc.o ctr.o cts.o gcm.o xts.o hmac.o cmac.o \
		    aes_generic.o \
		    sha1_generic.o sha256_generic.o sha512_generic.o \
		    sha3_generic.o \
		    lib-crypto-aes.o lib-crypto-gf128mul.o lib-crypto-memneq.o \
		    lib-crypto-sha1.o lib-crypto-sha256.o lib-crypto-utils.o

# Get the arch to add its objects to $(crypto-fips-objs) before transformation
-include $(srctree)/arch/$(ARCH)/crypto/fips140/Kbuild.fips140

# Transform to -fips.o naming
crypto-fips-objs := $(foreach o,$(crypto-fips-objs),$(o:.o=-fips.o))

$(obj)/%-fips.o: KBUILD_CFLAGS += $(FIPS140_CFLAGS)
$(obj)/%-fips.o: $(srctree)/crypto/%.c FORCE
	$(call if_changed_rule,cc_o_c)
$(obj)/lib-%-fips.o: $(srctree)/lib/%.c FORCE
	$(call if_changed_rule,cc_o_c)
$(obj)/lib-crypto-%-fips.o: $(srctree)/lib/crypto/%.c FORCE
	$(call if_changed_rule,cc_o_c)

fips140-objs := \
	fips140-alg-registration.o \
	fips140-module.o \
	fips140-refs.o \
	fips140-selftests.o \
	$(crypto-fips-objs)

obj-m += fips140.o

# Use custom linker script to collect initcalls
LDFLAGS_fips140.o += -T $(src)/fips140.lds

# Apply FIPS140_CFLAGS to the main module files (but not fips140-module.o)
CFLAGS_fips140-alg-registration.o += $(FIPS140_CFLAGS)
CFLAGS_fips140-selftests.o += $(FIPS140_CFLAGS)
