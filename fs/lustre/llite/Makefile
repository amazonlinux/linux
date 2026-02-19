obj-$(CONFIG_LUSTRE_FS)	+= lustre.o

lustre-y	:= dcache.o dir.o file.o llite_lib.o llite_nfs.o
lustre-y	+= rw.o lproc_llite.o namei.o symlink.o llite_mmap.o
lustre-y	+= xattr.o xattr_cache.o
lustre-y	+= rw26.o super25.o statahead.o xattr_security.o
lustre-y	+= glimpse.o
lustre-y	+= lcommon_cl.o
lustre-y	+= lcommon_misc.o
lustre-y	+= vvp_dev.o vvp_page.o vvp_io.o vvp_object.o
lustre-y	+= pcc.o crypto.o
lustre-y	+= llite_foreign.o llite_foreign_symlink.o
lustre-y 	+= acl.o

include $(srctree)/fs/lustre/Makefile.rules
