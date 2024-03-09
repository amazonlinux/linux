obj-$(CONFIG_LUSTREFSX_LIBCFS)	+= libcfs.o

libcfs-linux-objs	:= linux-prim.o
libcfs-linux-objs	+= linux-hash.o
libcfs-linux-objs	+= linux-wait.o
libcfs-linux-objs	+= glob.o
libcfs-linux-objs	+= xarray.o

libcfs-crypto-objs	:= crypto.o fname.o hkdf.o hooks.o keyring.o
libcfs-crypto-objs	+= keysetup.o keysetup_v1.o policy.o

libcfs-linux-objs	:= $(addprefix linux/,$(libcfs-linux-objs))
libcfs-crypto-objs	:= $(addprefix crypto/,$(libcfs-crypto-objs))


libcfs-all-objs		:= libcfs_cpu.o
libcfs-all-objs		+= debug.o fail.o module.o tracefile.o
libcfs-all-objs		+= libcfs_string.o hash.o workitem.o
libcfs-all-objs		+= libcfs_mem.o libcfs_lock.o
libcfs-all-objs		+= linux-crypto.o linux-crypto-adler.o

libcfs-y		+= $(libcfs-linux-objs) $(libcfs-all-objs)
libcfs-y		+= $(libcfs-crypto-objs)

ccflags-y		+= -I$(src)

include $(srctree)/drivers/staging/lustrefsx/Makefile.rules
