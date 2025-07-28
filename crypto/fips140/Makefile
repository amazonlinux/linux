# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the FIPS 140 kernel module
#

FIPS140_CFLAGS := -DBUILD_FIPS140_KO -include $(srctree)/crypto/fips140/fips140-defs.h

# Compile an extra copy of various crypto algorithms into the fips140 module
crypto-fips-objs := adiantum.o aegis128-core.o aes_generic.o aes_ti.o ansi_cprng.o \
		    anubis.o arc4.o aria_generic.o authenc.o authencesn.o \
		    blake2b_generic.o blowfish_common.o blowfish_generic.o \
		    camellia_generic.o cast5_generic.o cast6_generic.o cast_common.o \
		    cbc.o ccm.o chacha20poly1305.o chacha_generic.o cipher.o cmac.o \
		    crc32c_generic.o crc32_generic.o cryptd.o crypto_null.o ctr.o \
		    cts.o deflate.o des_generic.o dh.o dh_helper.o drbg.o ecb.o \
		    ecc.o ecdh.o ecdh_helper.o echainiv.o essiv.o fcrypt.o gcm.o \
		    geniv.o ghash-generic.o hctr2.o hkdf.o hmac.o \
		    jitterentropy.o jitterentropy-kcapi.o kdf_sp800108.o khazad.o \
		    lrw.o lz4.o lz4hc.o lzo.o lzo-rle.o md4.o md5.o michael_mic.o \
		    nhpoly1305.o pcbc.o pcrypt.o poly1305_generic.o polyval-generic.o \
		    rmd160.o seed.o seqiv.o serpent_generic.o sha1_generic.o \
		    sha256_generic.o sha3_generic.o sha512_generic.o sm3.o \
		    sm3_generic.o sm4.o sm4_generic.o streebog_generic.o tea.o \
		    twofish_common.o twofish_generic.o wp512.o xcbc.o xctr.o xts.o \
		    xxhash_generic.o \
		    lib-crypto-aes.o lib-crypto-arc4.o lib-crypto-chacha.o \
		    lib-crypto-des.o lib-crypto-gf128mul.o lib-crypto-memneq.o \
		    lib-crypto-poly1305.o lib-crypto-poly1305-donna64.o \
		    lib-crypto-libchacha.o lib-crypto-sha1.o lib-crypto-sha256.o \
		    lib-crypto-utils.o lib-lz4-lz4_compress.o lib-lz4-lz4_decompress.o \
		    lib-lz4-lz4hc_compress.o

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
$(obj)/lib-lz4-%-fips.o: $(srctree)/lib/lz4/%.c FORCE
	$(call if_changed_rule,cc_o_c)
$(obj)/lib-zstd-%-fips.o: $(srctree)/lib/zstd/%.c FORCE
	$(call if_changed_rule,cc_o_c)

fips140-objs := \
	fips140-alg-registration.o \
	fips140-module.o \
	fips140-refs.o \
	fips140-selftests.o \
	$(crypto-fips-objs)

obj-m += fips140.o

# Apply FIPS140_CFLAGS to the main module files (but not fips140-module.o)
CFLAGS_fips140-alg-registration.o += $(FIPS140_CFLAGS)
CFLAGS_fips140-selftests.o += $(FIPS140_CFLAGS)

# Special compilation flags for jitterentropy
CFLAGS_jitterentropy-fips.o := -O0
KASAN_SANITIZE_jitterentropy-fips.o = n
UBSAN_SANITIZE_jitterentropy-fips.o = n
