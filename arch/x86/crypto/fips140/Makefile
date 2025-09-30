
crypto-objs-y += fips140-var-redirect-fips.o

obj-y += fips140-var-redirect-main.o

# Explicit rules to compile same source to different objects
$(obj)/fips140-var-redirect-main.o: $(src)/fips140-var-redirect.c FORCE
	$(call if_changed_rule,cc_o_c)

$(obj)/fips140-var-redirect-fips.o: $(src)/fips140-var-redirect.c FORCE
	$(call if_changed_rule,cc_o_c)

CFLAGS_fips140-var-redirect-main.o += -I$(srctree)
CFLAGS_fips140-var-redirect-fips.o += -I$(srctree)
