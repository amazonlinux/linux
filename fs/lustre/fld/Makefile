obj-$(CONFIG_LUSTRE_LNET)        += fld.o

ccflags-y	+= -I$(srctree)/fs/lustre/include

fld-y		:= fld_request.o fld_cache.o lproc_fld.o

include $(srctree)/fs/lustre/Makefile.rules

