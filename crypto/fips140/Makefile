
crypto-objs-y += \
	fips140-module.o  \
	fips140-var-redirect-fips.o

obj-y += fips140-loader.o fips140-var-redirect-main.o

CFLAGS_fips140-fn-redirect.o += -I$(obj)
CFLAGS_fips140-module.o += -DFIPS140_CORE
CFLAGS_fips140-var-redirect-fips.o += -DFIPS140_CORE

# Explicit rules to compile same source to different objects
$(obj)/fips140-var-redirect-main.o: $(src)/fips140-var-redirect.c FORCE
	$(call if_changed_rule,cc_o_c)

$(obj)/fips140-var-redirect-fips.o: $(src)/fips140-var-redirect.c FORCE
	$(call if_changed_rule,cc_o_c)

CFLAGS_fips140-var-redirect-main.o += -I$(srctree)
CFLAGS_fips140-var-redirect-fips.o += -I$(srctree)

clean-files:= .fips140.order .fips140.symvers .fips140-fn-redirect.h .fips140.exported .fips140.hmac .fips140.ko.btf
ifdef CONFIG_CRYPTO_FIPS140_DUAL_VERSION
clean-files += .nonfips140.ko.btf
endif