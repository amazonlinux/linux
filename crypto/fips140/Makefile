
crypto-objs-y += \
	fips140-module.o 

obj-y += fips140-loader.o

CFLAGS_fips140-fn-redirect.o += -I$(obj)
CFLAGS_fips140-module.o += -DFIPS140_CORE

clean-files:= .fips140.order .fips140.symvers .fips140-fn-redirect.h .fips140.exported .fips140.hmac .fips140.ko.btf
ifdef CONFIG_CRYPTO_FIPS140_DUAL_VERSION
clean-files += .nonfips140.ko.btf
endif