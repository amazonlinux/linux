
crypto-objs-y += fips140-api-fips.o

obj-y += fips140-api-main.o

# Explicit rules to compile same source to different objects
$(obj)/fips140-api-main.o: $(src)/fips140-api.c FORCE
	$(call if_changed_rule,cc_o_c)

$(obj)/fips140-api-fips.o: $(src)/fips140-api.c FORCE
	$(call if_changed_rule,cc_o_c)

CFLAGS_fips140-api-main.o += -I$(srctree)
CFLAGS_fips140-api-fips.o += -I$(srctree)