# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the FIPS 140 kernel module
#

# Build builtin functions into the main kernel
obj-y += builtin/

FIPS140_CFLAGS := -DBUILD_FIPS140_KO -include $(srctree)/crypto/fips140/fips140-defs.h

# Compile an extra copy of ALL crypto algorithms into the fips140 module
# (excluding kernel API, test files, and architecture-specific files handled below)
crypto-fips-objs := aegis128-core.o authenc.o authencesn.o \
		    blake2b_generic.o \
		    cbc.o ccm.o cipher.o cmac.o \
		    crypto_null.o ctr.o \
		    cts.o \
		    ecb.o ecc.o echainiv.o essiv.o fips.o gcm.o \
		    geniv.o ghash-generic.o hash_info.o hctr2.o hkdf.o hmac.o \
		    jitterentropy.o jitterentropy-kcapi.o kdf_sp800108.o \
		    lrw.o md4.o md5.o \
		    pcbc.o polyval-generic.o \
		    rmd160.o seqiv.o \
		    sha1_generic.o sha256_generic.o sha3_generic.o sha512_generic.o \
		    sm3.o streebog_generic.o \
		    wp512.o xcbc.o xctr.o xor.o \
		    xts.o \
		    krb5/krb5_kdf.o krb5/rfc3961_simplified.o krb5/rfc3962_aes.o \
		    krb5/rfc6803_camellia.o krb5/rfc8009_aes2.o

# AES and DRBG (DRBG depends on AES, so both are conditional on CONFIG_CRYPTO_AES)
crypto-fips-objs-$(CONFIG_CRYPTO_AES) += aes_generic.o drbg.o

# nhpoly1305 depends on poly1305 core functions, so only include when nhpoly1305 is configured
crypto-fips-objs-$(CONFIG_CRYPTO_NHPOLY1305) += nhpoly1305.o

# Conditional lib-crypto objects (following lib/crypto/Makefile pattern)
crypto-fips-objs-$(CONFIG_CRYPTO_LIB_AES) += lib-crypto-aes.o
crypto-fips-objs-$(CONFIG_CRYPTO_LIB_ARC4) += lib-crypto-arc4.o
crypto-fips-objs-y += lib-crypto-chacha.o  # chacha is always builtin
crypto-fips-objs-$(CONFIG_CRYPTO_LIB_CHACHA_GENERIC) += lib-crypto-libchacha.o
crypto-fips-objs-$(CONFIG_CRYPTO_LIB_DES) += lib-crypto-des.o
crypto-fips-objs-$(CONFIG_CRYPTO_LIB_GF128MUL) += lib-crypto-gf128mul.o
crypto-fips-objs-$(CONFIG_CRYPTO_LIB_UTILS) += lib-crypto-memneq.o lib-crypto-utils.o
crypto-fips-objs-$(CONFIG_CRYPTO_LIB_POLY1305_GENERIC) += lib-crypto-poly1305.o lib-crypto-poly1305-donna64.o
crypto-fips-objs-$(CONFIG_CRYPTO_LIB_SHA1) += lib-crypto-sha1.o
crypto-fips-objs-$(CONFIG_CRYPTO_LIB_SHA256) += lib-crypto-sha256.o

# Conditional crypto objects (following main crypto Makefiles pattern)
crypto-fips-objs-$(CONFIG_FIPS_SIGNATURE_SELFTEST_RSA) += asymmetric_keys/selftest_rsa.o
crypto-fips-objs-$(CONFIG_FIPS_SIGNATURE_SELFTEST_ECDSA) += asymmetric_keys/selftest_ecdsa.o
crypto-fips-objs-$(CONFIG_CRYPTO_KRB5_SELFTESTS) += krb5/selftest.o krb5/selftest_data.o
crypto-fips-objs-$(CONFIG_ASYNC_CORE) += async_tx/async_tx.o
crypto-fips-objs-$(CONFIG_ASYNC_MEMCPY) += async_tx/async_memcpy.o
crypto-fips-objs-$(CONFIG_ASYNC_XOR) += async_tx/async_xor.o
crypto-fips-objs-$(CONFIG_ASYNC_PQ) += async_tx/async_pq.o
crypto-fips-objs-$(CONFIG_ASYNC_RAID6_RECOV) += async_tx/async_raid6_recov.o
crypto-fips-objs-$(CONFIG_ASYNC_RAID6_TEST) += async_tx/raid6test.o
crypto-fips-objs-$(CONFIG_ASYMMETRIC_KEY_TYPE) += asymmetric_keys/asymmetric_type.o asymmetric_keys/restrict.o
crypto-fips-objs-$(CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE) += asymmetric_keys/public_key.o
crypto-fips-objs-$(CONFIG_X509_CERTIFICATE_PARSER) += asymmetric_keys/x509.asn1.o asymmetric_keys/x509_akid.asn1.o asymmetric_keys/x509_cert_parser.o asymmetric_keys/x509_loader.o asymmetric_keys/x509_public_key.o
crypto-fips-objs-$(CONFIG_FIPS_SIGNATURE_SELFTEST) += asymmetric_keys/selftest.o
crypto-fips-objs-$(CONFIG_PKCS8_PRIVATE_KEY_PARSER) += asymmetric_keys/pkcs8.asn1.o asymmetric_keys/pkcs8_parser.o
crypto-fips-objs-$(CONFIG_PKCS7_MESSAGE_PARSER) += asymmetric_keys/pkcs7.asn1.o asymmetric_keys/pkcs7_parser.o asymmetric_keys/pkcs7_trust.o asymmetric_keys/pkcs7_verify.o
crypto-fips-objs-$(CONFIG_PKCS7_TEST_KEY) += asymmetric_keys/pkcs7_key_type.o
crypto-fips-objs-$(CONFIG_SIGNED_PE_FILE_VERIFICATION) += asymmetric_keys/verify_pefile.o asymmetric_keys/mscode_parser.o asymmetric_keys/mscode.asn1.o
crypto-fips-objs-$(CONFIG_CRYPTO_CURVE25519) += curve25519-generic.o
crypto-fips-objs-$(CONFIG_ZSTD_COMPRESS) += zstd.o
crypto-fips-objs-$(CONFIG_CRYPTO_842) += 842.o
crypto-fips-objs-$(CONFIG_CRYPTO_ADIANTUM) += adiantum.o
crypto-fips-objs-$(CONFIG_CRYPTO_AES_TI) += aes_ti.o
crypto-fips-objs-$(CONFIG_CRYPTO_ANUBIS) += anubis.o
crypto-fips-objs-$(CONFIG_CRYPTO_ARC4) += arc4.o
crypto-fips-objs-$(CONFIG_CRYPTO_ARIA) += aria_generic.o
crypto-fips-objs-$(CONFIG_CRYPTO_BLOWFISH) += blowfish_generic.o
crypto-fips-objs-$(CONFIG_CRYPTO_BLOWFISH_COMMON) += blowfish_common.o
crypto-fips-objs-$(CONFIG_CRYPTO_CAMELLIA) += camellia_generic.o
crypto-fips-objs-$(CONFIG_CRYPTO_CAST_COMMON) += cast_common.o
crypto-fips-objs-$(CONFIG_CRYPTO_CAST5) += cast5_generic.o
crypto-fips-objs-$(CONFIG_CRYPTO_CAST6) += cast6_generic.o
crypto-fips-objs-$(CONFIG_CRYPTO_CHACHA20) += chacha_generic.o
crypto-fips-objs-$(CONFIG_CRYPTO_CRC32C) += crc32c_generic.o
crypto-fips-objs-$(CONFIG_CRYPTO_CRC32) += crc32_generic.o
crypto-fips-objs-$(CONFIG_CRYPTO_CRYPTD) += cryptd.o
crypto-fips-objs-$(CONFIG_CRYPTO_DEFLATE) += deflate.o
crypto-fips-objs-$(CONFIG_CRYPTO_DES) += des_generic.o
crypto-fips-objs-$(CONFIG_CRYPTO_DH) += dh.o dh_helper.o
crypto-fips-objs-$(CONFIG_CRYPTO_ECDH) += ecdh.o ecdh_helper.o
crypto-fips-objs-$(CONFIG_CRYPTO_ECDSA) += ecdsa.o ecdsa-p1363.o ecdsa-x962.o ecdsasignature.asn1.o
crypto-fips-objs-$(CONFIG_CRYPTO_ECRDSA) += ecrdsa.o ecrdsa_params.asn1.o ecrdsa_pub_key.asn1.o
crypto-fips-objs-$(CONFIG_CRYPTO_FCRYPT) += fcrypt.o
crypto-fips-objs-$(CONFIG_CRYPTO_KHAZAD) += khazad.o
crypto-fips-objs-$(CONFIG_CRYPTO_KRB5ENC) += krb5enc.o
# LZ4 handling
crypto-fips-objs-$(CONFIG_CRYPTO_LZ4) += lz4.o
crypto-fips-objs-$(CONFIG_CRYPTO_LZ4) += lib-lz4_decompress.o
crypto-fips-objs-$(CONFIG_CRYPTO_LZ4HC) += lz4hc.o
crypto-fips-objs-$(CONFIG_CRYPTO_LZ4HC) += lib-lz4_compress.o lib-lz4hc_compress.o
crypto-fips-objs-$(CONFIG_CRYPTO_LZO) += lzo.o lzo-rle.o
crypto-fips-objs-$(CONFIG_CRYPTO_MICHAEL_MIC) += michael_mic.o
crypto-fips-objs-$(CONFIG_CRYPTO_PCRYPT) += pcrypt.o
crypto-fips-objs-$(CONFIG_CRYPTO_POLY1305) += poly1305_generic.o
crypto-fips-objs-$(CONFIG_CRYPTO_RSA) += rsa.o rsa_helper.o rsa-pkcs1pad.o rsaprivkey.asn1.o rsapubkey.asn1.o rsassa-pkcs1.o
crypto-fips-objs-$(CONFIG_CRYPTO_SEED) += seed.o
crypto-fips-objs-$(CONFIG_CRYPTO_SERPENT) += serpent_generic.o
crypto-fips-objs-$(CONFIG_CRYPTO_SM4) += sm4.o
crypto-fips-objs-$(CONFIG_CRYPTO_SM4_GENERIC) += sm4_generic.o
crypto-fips-objs-$(CONFIG_CRYPTO_TEA) += tea.o
crypto-fips-objs-$(CONFIG_CRYPTO_TWOFISH) += twofish_generic.o
crypto-fips-objs-$(CONFIG_CRYPTO_TWOFISH_COMMON) += twofish_common.o
crypto-fips-objs-$(CONFIG_CRYPTO_XXHASH) += xxhash_generic.o
# Include only built-in (y) configurations
crypto-fips-objs += $(crypto-fips-objs-y)

# Architecture-specific crypto algorithms (following main kernel Makefile pattern)
ifeq ($(ARCH),arm)
CFLAGS_aegis128-neon-inner-fips.o += -ffreestanding -march=armv8-a -mfloat-abi=softfp
CFLAGS_aegis128-neon-inner-fips.o += -mfpu=crypto-neon-fp-armv8
crypto-fips-objs += aegis128-neon.o aegis128-neon-inner.o
endif
ifeq ($(ARCH),arm64)
aegis128-cflags-y := -ffreestanding -mcpu=generic+crypto
aegis128-cflags-$(CONFIG_CC_IS_GCC) += -ffixed-q16 -ffixed-q17 -ffixed-q18 \
				       -ffixed-q19 -ffixed-q20 -ffixed-q21 \
				       -ffixed-q22 -ffixed-q23 -ffixed-q24 \
				       -ffixed-q25 -ffixed-q26 -ffixed-q27 \
				       -ffixed-q28 -ffixed-q29 -ffixed-q30 \
				       -ffixed-q31
CFLAGS_aegis128-neon-inner-fips.o += $(aegis128-cflags-y)
CFLAGS_REMOVE_aegis128-neon-inner-fips.o += -mgeneral-regs-only
crypto-fips-objs += aegis128-neon.o aegis128-neon-inner.o
endif
# Enable <arm_neon.h>
CFLAGS_aegis128-neon-inner-fips.o += -isystem $(shell $(CC) -print-file-name=include)

# Get the arch to add its objects to $(crypto-fips-objs) before transformation
-include $(srctree)/arch/$(ARCH)/crypto/fips140/Kbuild.fips140


# ASN.1 generation rules - generate our own ASN.1 files in FIPS module
$(obj)/%.asn1.c $(obj)/%.asn1.h: $(srctree)/crypto/%.asn1 $(objtree)/scripts/asn1_compiler
	$(objtree)/scripts/asn1_compiler $< $(obj)/$*.asn1.c $(obj)/$*.asn1.h

$(obj)/asymmetric_keys/%.asn1.c $(obj)/asymmetric_keys/%.asn1.h: $(srctree)/crypto/asymmetric_keys/%.asn1 $(objtree)/scripts/asn1_compiler
	@mkdir -p $(obj)/asymmetric_keys
	$(objtree)/scripts/asn1_compiler $< $(obj)/asymmetric_keys/$*.asn1.c $(obj)/asymmetric_keys/$*.asn1.h

# ASN.1 compilation rule for generated files
$(obj)/%.asn1-fips.o: KBUILD_CFLAGS += $(FIPS140_CFLAGS) -I$(obj)
$(obj)/%.asn1-fips.o: $(obj)/%.asn1.c $(obj)/%.asn1.h  FORCE
	$(call if_changed_rule,cc_o_c)
$(obj)/asymmetric_keys/%.asn1-fips.o: KBUILD_CFLAGS += $(FIPS140_CFLAGS) -I$(obj)
$(obj)/asymmetric_keys/%.asn1-fips.o: $(obj)/asymmetric_keys/%.asn1.c $(obj)/asymmetric_keys/%.asn1.h FORCE
	@mkdir -p $(obj)/asymmetric_keys
	$(call if_changed_rule,cc_o_c)

# Header dependencies for files that include ASN.1 headers
$(obj)/rsa_helper-fips.o: $(obj)/rsapubkey.asn1.h $(obj)/rsaprivkey.asn1.h
$(obj)/ecdsa-x962-fips.o: $(obj)/ecdsasignature.asn1.h
$(obj)/ecrdsa-fips.o: $(obj)/ecrdsa_params.asn1.h $(obj)/ecrdsa_pub_key.asn1.h

# Transform to -fips.o naming
crypto-fips-objs := $(foreach o,$(crypto-fips-objs),$(o:.o=-fips.o))

# Add FIPS 140 test suites to get FIPS140_CFLAGS and common macros
crypto-fips-objs += fips140-testsuites.o

$(obj)/%-fips.o: KBUILD_CFLAGS += $(FIPS140_CFLAGS) -I$(obj)
$(obj)/%-fips.o: $(srctree)/crypto/%.c FORCE
	$(call if_changed_rule,cc_o_c)
$(obj)/asymmetric_keys/%-fips.o: KBUILD_CFLAGS += $(FIPS140_CFLAGS) -I$(obj)
$(obj)/asymmetric_keys/%-fips.o: $(srctree)/crypto/asymmetric_keys/%.c FORCE
	@mkdir -p $(obj)/asymmetric_keys
	$(call if_changed_rule,cc_o_c)
$(obj)/async_tx/%-fips.o: KBUILD_CFLAGS += $(FIPS140_CFLAGS)
$(obj)/async_tx/%-fips.o: $(srctree)/crypto/async_tx/%.c FORCE
	@mkdir -p $(obj)/async_tx
	$(call if_changed_rule,cc_o_c)
$(obj)/krb5/%-fips.o: KBUILD_CFLAGS += $(FIPS140_CFLAGS)
$(obj)/krb5/%-fips.o: $(srctree)/crypto/krb5/%.c FORCE
	@mkdir -p $(obj)/krb5
	$(call if_changed_rule,cc_o_c)
$(obj)/lib-%-fips.o: KBUILD_CFLAGS += $(FIPS140_CFLAGS)
$(obj)/lib-%-fips.o: $(srctree)/lib/%.c FORCE
	$(call if_changed_rule,cc_o_c)
$(obj)/lib-crypto-%-fips.o: KBUILD_CFLAGS += $(FIPS140_CFLAGS)
$(obj)/lib-crypto-%-fips.o: $(srctree)/lib/crypto/%.c FORCE
	$(call if_changed_rule,cc_o_c)
$(obj)/lib-lz4%-fips.o: KBUILD_CFLAGS += $(FIPS140_CFLAGS)
$(obj)/lib-lz4%-fips.o: $(srctree)/lib/lz4/lz4%.c FORCE
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

# Explicit rule to create fips140.ko from fips140.o
$(obj)/fips140.ko: $(addprefix $(obj)/,$(fips140-objs)) FORCE
	$(call if_changed,link_module)

# Generate embedded module object for builtin loading
ifeq ($(ARCH),x86)
quiet_cmd_embed_ko = EMBED   $@
      cmd_embed_ko = $(OBJCOPY) -I binary -O elf64-x86-64 -B i386:x86-64 \
		--rename-section .data=.fips140_data,alloc,load,readonly,data,contents \
		$< $@

$(obj)/fips140-embedded.o: $(obj)/fips140.ko FORCE
	$(call if_changed,embed_ko)
endif

# Only include embedded object if building fips140-embedded target and fips140.ko exists
ifdef FIPS140_EMBED
# Include loader in built-in.a for linking into vmlinux
obj-y += fips140-loader.o
ifneq ($(wildcard $(obj)/fips140.ko),)
obj-y += fips140-embedded.o
endif
endif