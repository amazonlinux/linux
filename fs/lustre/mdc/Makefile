obj-$(CONFIG_LUSTRE_FS)	+= mdc.o

mdc-y		:= mdc_request.o mdc_reint.o lproc_mdc.o mdc_lib.o mdc_locks.o
mdc-y		+= mdc_changelog.o mdc_dev.o
mdc-y		+= mdc_acl.o

include $(srctree)/fs/lustre/Makefile.rules
