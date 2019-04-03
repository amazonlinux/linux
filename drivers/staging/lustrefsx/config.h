/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* enable libcfs CDEBUG, CWARN */
#define CDEBUG_ENABLED 1

/* enable libcfs ENTRY/EXIT */
#define CDEBUG_ENTRY_EXIT 1

/* enable page state tracking code */
/* #undef CONFIG_DEBUG_PAGESTATE_TRACKING */

/* enable encryption for ldiskfs */
/* #undef CONFIG_LDISKFS_FS_ENCRYPTION */

/* posix acls for ldiskfs */
/* #undef CONFIG_LDISKFS_FS_POSIX_ACL */

/* enable rw access for ldiskfs */
/* #undef CONFIG_LDISKFS_FS_RW */

/* fs security for ldiskfs */
/* #undef CONFIG_LDISKFS_FS_SECURITY */

/* extened attributes for ldiskfs */
/* #undef CONFIG_LDISKFS_FS_XATTR */

/* Max LNET payload */
#define CONFIG_LNET_MAX_PAYLOAD LNET_MTU

/* enable invariant checking */
/* #undef CONFIG_LUSTRE_DEBUG_EXPENSIVE_CHECK */

/* IOCTL Buffer Size */
#define CONFIG_LUSTRE_OBD_MAX_IOCTL_BUFFER 8192

/* kernel has cpu affinity support */
/* #undef CPU_AFFINITY */

/* both i_dentry/d_alias uses list */
/* #undef DATA_FOR_LLITE_IS_LIST */

/* name of ldiskfs debug program */
#define DEBUGFS "debugfs"

/* name of ldiskfs dump program */
#define DUMPE2FS "dumpe2fs"

/* name of ldiskfs fsck program */
#define E2FSCK "e2fsck"

/* name of ldiskfs e2fsprogs package */
#define E2FSPROGS "e2fsprogs"

/* name of ldiskfs label program */
#define E2LABEL "e2label"

/* do data checksums */
#define ENABLE_CHECKSUM 1

/* Use the Pinger */
#define ENABLE_PINGER 1

/* Define to 1 if you have the <asm/types.h> header file. */
#define HAVE_ASM_TYPES_H 1

/* backing_dev_info exist */
/* #undef HAVE_BACKING_DEV_INFO */

/* BDI_CAP_MAP_COPY exist */
/* #undef HAVE_BDI_CAP_MAP_COPY */

/* bio_endio takes only one argument */
#define HAVE_BIO_ENDIO_USES_ONE_ARG 1

/* bio_end_sector is defined */
#define HAVE_BIO_END_SECTOR 1

/* 'bio_integrity_enabled' is available */
/* #undef HAVE_BIO_INTEGRITY_ENABLED */

/* 'bi_bdev' is available */
/* #undef HAVE_BI_BDEV */

/* struct bio has bi_cnt */
/* #undef HAVE_BI_CNT */

/* struct bio has bi_rw */
/* #undef HAVE_BI_RW */

/* 'bi_status' is available */
#define HAVE_BI_STATUS 1

/* blkdev_get_by_dev is exported by the kernel */
#define HAVE_BLKDEV_GET_BY_DEV 1

/* Define to 1 if you have the <blkid/blkid.h> header file. */
/* #undef HAVE_BLKID_BLKID_H */

/* blk_plug struct exists */
#define HAVE_BLK_PLUG 1

/* blk_queue_max_segments is defined */
#define HAVE_BLK_QUEUE_MAX_SEGMENTS 1

/* kernel has struct bvec_iter */
#define HAVE_BVEC_ITER 1

/* cache_head has hlist cache_list */
#define HAVE_CACHE_HEAD_HLIST 1

/* have cache_register */
/* #undef HAVE_CACHE_REGISTER */

/* cancel_dirty_page is still available */
/* #undef HAVE_CANCEL_DIRTY_PAGE */

/* kernel has clean_bdev_aliases */
#define HAVE_CLEAN_BDEV_ALIASES 1

/* have clear_inode */
#define HAVE_CLEAR_INODE 1

/* compat rdma found */
/* #undef HAVE_COMPAT_RDMA */

/* cpumap_print_to_pagebuf is available */
#define HAVE_CPUMASK_PRINT_TO_PAGEBUF 1

/* kernel compiled with CRC32 functions */
#define HAVE_CRC32 1

/* struct cred has member tgcred */
/* #undef HAVE_CRED_TGCRED */

/* crypto hash helper functions are available */
#define HAVE_CRYPTO_HASH_HELPERS 1

/* current_time() has replaced CURRENT_TIME */
#define HAVE_CURRENT_TIME 1

/* dcache_lock is exist */
/* #undef HAVE_DCACHE_LOCK */

/* kernel export delete_from_page_cache */
#define HAVE_DELETE_FROM_PAGE_CACHE 1

/* dentry.d_child exist */
#define HAVE_DENTRY_D_CHILD 1

/* hlist dentry.d_u.d_alias exist */
#define HAVE_DENTRY_D_U_D_ALIAS 1

/* dentry_open uses struct path as first argument */
#define HAVE_DENTRY_OPEN_USE_PATH 1

/* direct_IO need 2 arguments */
#define HAVE_DIRECTIO_2ARGS 1

/* direct IO uses iov_iter */
/* #undef HAVE_DIRECTIO_ITER */

/* dirty_inode super_operation takes flag */
#define HAVE_DIRTY_INODE_HAS_FLAG 1

/* dir_context exist */
#define HAVE_DIR_CONTEXT 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Have dmu_object_alloc_dnsize in ZFS */
/* #undef HAVE_DMU_OBJECT_ALLOC_DNSIZE */

/* Have dmu_objset_disown() with 3 args */
/* #undef HAVE_DMU_OBJSET_DISOWN_3ARG */

/* Have dmu_objset_own() with 6 args */
/* #undef HAVE_DMU_OBJSET_OWN_6ARG */

/* Have 6 argument dmu_pretch in ZFS */
/* #undef HAVE_DMU_PREFETCH_6ARG */

/* Have dmu_read_by_dnode() in ZFS */
/* #undef HAVE_DMU_READ_BY_DNODE */

/* Have dmu_tx_hold_write_by_dnode() in ZFS */
/* #undef HAVE_DMU_TX_HOLD_WRITE_BY_DNODE */

/* Have dmu_tx_hold_zap_by_dnode() in ZFS */
/* #undef HAVE_DMU_TX_HOLD_ZAP_BY_DNODE */

/* Have dmu_tx_mark_netfree */
/* #undef HAVE_DMU_TX_MARK_NETFREE */

/* Have native dnode accounting in ZFS */
/* #undef HAVE_DMU_USEROBJ_ACCOUNTING */

/* Have dmu_write_by_dnode() in ZFS */
/* #undef HAVE_DMU_WRITE_BY_DNODE */

/* quotactl_ops.set_dqblk takes struct fs_disk_quota */
/* #undef HAVE_DQUOT_FS_DISK_QUOTA */

/* quotactl_ops.set_dqblk takes struct kqid */
#define HAVE_DQUOT_KQID 1

/* quotactl_ops.set_dqblk takes struct qc_dqblk */
#define HAVE_DQUOT_QC_DQBLK 1

/* dquot_suspend is defined */
#define HAVE_DQUOT_SUSPEND 1

/* Have dsl_pool_config_enter/exit in ZFS */
/* #undef HAVE_DSL_POOL_CONFIG */

/* Have dsl_sync_task_do_nowait in ZFS */
/* #undef HAVE_DSL_SYNC_TASK_DO_NOWAIT */

/* dump_trace want address argument */
/* #undef HAVE_DUMP_TRACE_ADDRESS */

/* d_compare need 4 arguments */
#define HAVE_D_COMPARE_4ARGS 1

/* d_compare need 5 arguments */
/* #undef HAVE_D_COMPARE_5ARGS */

/* d_compare need 7 arguments */
/* #undef HAVE_D_COMPARE_7ARGS */

/* d_count exist */
#define HAVE_D_COUNT 1

/* d_delete first parameter declared is not const */
#define HAVE_D_DELETE_CONST const

/* have d_make_root */
#define HAVE_D_MAKE_ROOT 1

/* have parent inode as parameter */
#define HAVE_ENCODE_FH_PARENT 1

/* Define to 1 if you have the <endian.h> header file. */
#define HAVE_ENDIAN_H 1

/* Define to 1 if you have the <ext2fs/ext2fs.h> header file. */
/* #undef HAVE_EXT2FS_EXT2FS_H */

/* ext4_bread takes 4 arguments */
/* #undef HAVE_EXT4_BREAD_4ARGS */

/* i_dquot is in ext4_inode_info */
/* #undef HAVE_EXT4_INFO_DQUOT */

/* ext4_free_blocks do not require struct buffer_head */
/* #undef HAVE_EXT_FREE_BLOCK_WITH_BUFFER_HEAD */

/* Linux kernel has ext_pblock */
/* #undef HAVE_EXT_PBLOCK */

/* file handle and related syscalls are supported */
#define HAVE_FHANDLE_GLIBC_SUPPORT 1

/* kernel supports fhandles and related syscalls */
#define HAVE_FHANDLE_SYSCALLS 1

/* kernel has file_dentry */
#define HAVE_FILE_DENTRY 1

/* file_operations.fsync takes 2 arguments */
/* #undef HAVE_FILE_FSYNC_2ARGS */

/* file_operations.fsync takes 4 arguments */
#define HAVE_FILE_FSYNC_4ARGS 1

/* struct file has member f_inode */
#define HAVE_FILE_F_INODE 1

/* file_inode() has been defined */
#define HAVE_FILE_INODE 1

/* generic_file_llseek_size is exported by the kernel */
#define HAVE_FILE_LLSEEK_SIZE 1

/* kernel has generic_file_llseek_size with 5 args */
#define HAVE_FILE_LLSEEK_SIZE_5ARGS 1

/* file_operations.[read|write]_iter functions exist */
#define HAVE_FILE_OPERATIONS_READ_WRITE_ITER 1

/* filldir_t needs struct dir_context as argument */
#define HAVE_FILLDIR_USE_CTX 1

/* fpu/api.h is present */
#define HAVE_FPU_API_HEADER 1

/* struct file_system_type has mount field */
#define HAVE_FSTYPE_MOUNT 1

/* fs_struct.lock use rwlock */
/* #undef HAVE_FS_STRUCT_RWLOCK */

/* fs_struct use seqcount */
#define HAVE_FS_STRUCT_SEQCOUNT 1

/* full_name_hash need 3 arguments */
#define HAVE_FULL_NAME_HASH_3ARGS 1

/* generic_permission taken 2 arguments */
#define HAVE_GENERIC_PERMISSION_2ARGS 1

/* generic_permission taken 4 arguments */
/* #undef HAVE_GENERIC_PERMISSION_4ARGS */

/* generic_write_sync need 2 arguments */
#define HAVE_GENERIC_WRITE_SYNC_2ARGS 1

/* Define to 1 if you have the `gethostbyname' function. */
#define HAVE_GETHOSTBYNAME 1

/* get_user_pages takes 6 arguments */
/* #undef HAVE_GET_USER_PAGES_6ARG */

/* get_user_pages takes gup_flags in arguments */
#define HAVE_GET_USER_PAGES_GUP_FLAGS 1

/* struct group_info has member gid */
#define HAVE_GROUP_INFO_GID 1

/* Define this is if you enable gss */
/* #undef HAVE_GSS */

/* Define this if you enable gss keyring backend */
/* #undef HAVE_GSS_KEYRING */

/* Define this if the Kerberos GSS library supports gss_krb5_ccache_name */
/* #undef HAVE_GSS_KRB5_CCACHE_NAME */

/* Define this if you have Heimdal Kerberos libraries */
/* #undef HAVE_HEIMDAL */

/* hlist_add_after is available */
/* #undef HAVE_HLIST_ADD_AFTER */

/* hlist_for_each_entry has 3 args */
#define HAVE_HLIST_FOR_EACH_3ARG 1

/* hotplug state machine is supported */
#define HAVE_HOTPLUG_STATE_MACHINE 1

/* ib_alloc_fast_reg_mr is defined */
/* #undef HAVE_IB_ALLOC_FAST_REG_MR */

/* ib_alloc_pd has 2 arguments */
#define HAVE_IB_ALLOC_PD_2ARGS 1

/* struct ib_cq_init_attr is used by ib_create_cq */
#define HAVE_IB_CQ_INIT_ATTR 1

/* struct ib_device.attrs is defined */
#define HAVE_IB_DEVICE_ATTRS 1

/* ib_get_dma_mr is defined */
/* #undef HAVE_IB_GET_DMA_MR */

/* function ib_inc_rkey exist */
#define HAVE_IB_INC_RKEY 1

/* ib_map_mr_sg exists */
#define HAVE_IB_MAP_MR_SG 1

/* ib_map_mr_sg has 5 arguments */
#define HAVE_IB_MAP_MR_SG_5ARGS 1

/* struct ib_rdma_wr is defined */
#define HAVE_IB_RDMA_WR 1

/* inode_operations .getattr member function can gather advance stats */
#define HAVE_INODEOPS_ENHANCED_GETATTR 1

/* inode_operations has .truncate member function */
/* #undef HAVE_INODEOPS_TRUNCATE */

/* inode_operations use umode_t as parameter */
#define HAVE_INODEOPS_USE_UMODE_T 1

/* inode->i_alloc_sem is killed and use inode_dio_wait */
#define HAVE_INODE_DIO_WAIT 1

/* inode.i_rcu exists */
#define HAVE_INODE_I_RCU 1

/* inode_lock is defined */
#define HAVE_INODE_LOCK 1

/* inode_owner_or_capable exist */
#define HAVE_INODE_OWNER_OR_CAPABLE 1

/* inode_operations->permission has two args */
#define HAVE_INODE_PERMISION_2ARGS 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* address_space_operations.invalidatepage needs 3 arguments */
#define HAVE_INVALIDATE_RANGE 1

/* have in_compat_syscall */
#define HAVE_IN_COMPAT_SYSCALL 1

/* inode_operations->rename need flags as argument */
#define HAVE_IOPS_RENAME_WITH_FLAGS 1

/* have iop atomic_open */
#define HAVE_IOP_ATOMIC_OPEN 1

/* generic_readlink has been removed */
/* #undef HAVE_IOP_GENERIC_READLINK */

/* inode_operations has .get_acl member function */
#define HAVE_IOP_GET_ACL 1

/* have iop get_link */
#define HAVE_IOP_GET_LINK 1

/* inode_operations has .set_acl member function */
#define HAVE_IOP_SET_ACL 1

/* inode_operations has {get,set,remove}xattr members */
/* #undef HAVE_IOP_XATTR */

/* iov_iter_init handles directional tag */
#define HAVE_IOV_ITER_INIT_DIRECTION 1

/* iov_iter_rw exist */
#define HAVE_IOV_ITER_RW 1

/* iov_iter_truncate exists */
#define HAVE_IOV_ITER_TRUNCATE 1

/* is_sxid is defined */
#define HAVE_IS_SXID 1

/* i_uid_read is present */
#define HAVE_I_UID_READ 1

/* kernel_locked is defined */
/* #undef HAVE_KERNEL_LOCKED */

/* 'struct sock' accept function requires bool argument */
#define HAVE_KERN_SOCK_ACCEPT_FLAG_ARG 1

/* struct key_match_data exist */
#define HAVE_KEY_MATCH_DATA 1

/* payload.data is an array */
#define HAVE_KEY_PAYLOAD_DATA_ARRAY 1

/* key_type->instantiate has two args */
/* #undef HAVE_KEY_TYPE_INSTANTIATE_2ARGS */

/* ki_left exist */
/* #undef HAVE_KIOCB_KI_LEFT */

/* ki_nbytes field exist */
/* #undef HAVE_KI_NBYTES */

/* have kmap_atomic has only 1 argument */
#define HAVE_KMAP_ATOMIC_HAS_1ARG 1

/* kmap_to_page is exported by the kernel */
/* #undef HAVE_KMAP_TO_PAGE */

/* Define this if you have MIT Kerberos libraries */
/* #undef HAVE_KRB5 */

/* Define this if the function krb5int_derive_key is available */
/* #undef HAVE_KRB5INT_DERIVE_KEY */

/* Define this if the function krb5_derive_key is available */
/* #undef HAVE_KRB5_DERIVE_KEY */

/* Define this if the function krb5_get_error_message is available */
/* #undef HAVE_KRB5_GET_ERROR_MESSAGE */

/* Define this if the function krb5_get_init_creds_opt_set_addressless is
   available */
/* #undef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_ADDRESSLESS */

/* kernel has kstrtoul */
#define HAVE_KSTRTOUL 1

/* kthread_worker found */
/* #undef HAVE_KTHREAD_WORK */

/* ktime_add is available */
#define HAVE_KTIME_ADD 1

/* ktime_after is available */
#define HAVE_KTIME_AFTER 1

/* ktime_before is available */
#define HAVE_KTIME_BEFORE 1

/* ktime_compare is available */
#define HAVE_KTIME_COMPARE 1

/* 'ktime_get_real_seconds' is available */
#define HAVE_KTIME_GET_REAL_SECONDS 1

/* 'ktime_get_real_ts64' is available */
#define HAVE_KTIME_GET_REAL_TS64 1

/* 'ktime_get_seconds' is available */
#define HAVE_KTIME_GET_SECONDS 1

/* 'ktime_get_ts64' is available */
#define HAVE_KTIME_GET_TS64 1

/* 'ktime_to_timespec64' is available */
#define HAVE_KTIME_TO_TIMESPEC64 1

/* enable use of ldiskfsprogs package */
/* #undef HAVE_LDISKFSPROGS */

/* kernel has ext4_map_blocks */
/* #undef HAVE_LDISKFS_MAP_BLOCKS */

/* Enable ldiskfs osd */
/* #undef HAVE_LDISKFS_OSD */

/* libefence support is requested */
/* #undef HAVE_LIBEFENCE */

/* Define to 1 if you have the `keyutils' library (-lkeyutils). */
/* #undef HAVE_LIBKEYUTILS */

/* build with libmount */
/* #undef HAVE_LIBMOUNT */

/* use libpthread for libcfs library */
#define HAVE_LIBPTHREAD 1

/* readline library is available */
/* #undef HAVE_LIBREADLINE */

/* Define to 1 if you have the <linux/random.h> header file. */
#define HAVE_LINUX_RANDOM_H 1

/* Define to 1 if you have the <linux/types.h> header file. */
#define HAVE_LINUX_TYPES_H 1

/* Define to 1 if you have the <linux/unistd.h> header file. */
#define HAVE_LINUX_UNISTD_H 1

/* Define to 1 if you have the <linux/version.h> header file. */
#define HAVE_LINUX_VERSION_H 1

/* lock-manager ops renamed to lm_xxx */
#define HAVE_LM_XXX_LOCK_MANAGER_OPS 1

/* kernel has locks_lock_file_wait */
#define HAVE_LOCKS_LOCK_FILE_WAIT 1

/* kernel has LOOP_CTL_GET_FREE */
#define HAVE_LOOP_CTL_GET_FREE 1

/* Enable lru resize support */
#define HAVE_LRU_RESIZE_SUPPORT 1

/* Define this if the Kerberos GSS library supports
   gss_krb5_export_lucid_sec_context */
/* #undef HAVE_LUCID_CONTEXT_SUPPORT */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* address_space_operations.migratepage has 4 args */
#define HAVE_MIGRATEPAGE_4ARGS 1

/* kernel has include/linux/migrate.h */
#define HAVE_MIGRATE_H 1

/* kernel has include/linux/migrate_mode.h */
/* #undef HAVE_MIGRATE_MODE_H */

/* kernel module loading is possible */
#define HAVE_MODULE_LOADING_SUPPORT 1

/* Define to 1 if you have the `name_to_handle_at' function. */
#define HAVE_NAME_TO_HANDLE_AT 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* cancel_dirty_page with one arguement is available */
#define HAVE_NEW_CANCEL_DIRTY_PAGE 1

/* 'kernel_write' aligns with read/write helpers */
#define HAVE_NEW_KERNEL_WRITE 1

/* with oldsize */
/* #undef HAVE_OLDSIZE_TRUNCATE_PAGECACHE */

/* OpenSSL HMAC functions needed for SSK */
/* #undef HAVE_OPENSSL_SSK */

/* 'pagevec_init' takes one parameter */
/* #undef HAVE_PAGEVEC_INIT_ONE_PARAM */

/* have PCLMULQDQ instruction */
#define HAVE_PCLMULQDQ 1

/* percpu_counter_init uses GFP_* flag */
#define HAVE_PERCPU_COUNTER_INIT_GFP_FLAG 1

/* 'struct nsproxy' has 'pid_ns_for_children' */
#define HAVE_PID_NS_FOR_CHILDREN 1

/* posix_acl_to_xattr takes struct user_namespace */
#define HAVE_POSIXACL_USER_NS 1

/* 'posix_acl_update_mode' is available */
#define HAVE_POSIX_ACL_UPDATE_MODE 1

/* posix_acl_valid takes struct user_namespace */
#define HAVE_POSIX_ACL_VALID_USER_NS 1

/* proc_remove is defined */
#define HAVE_PROC_REMOVE 1

/* get_projid function exists */
#define HAVE_PROJECT_QUOTA 1

/* inode->i_nlink is protected from direct modification */
#define HAVE_PROTECT_I_NLINK 1

/* have quota64 */
/* #undef HAVE_QUOTA64 */

/* radix_tree_exceptional_entry exist */
#define HAVE_RADIX_EXCEPTION_ENTRY 1

/* rdma_create_id wants 4 args */
/* #undef HAVE_RDMA_CREATE_ID_4ARG */

/* rdma_create_id wants 5 args */
#define HAVE_RDMA_CREATE_ID_5ARG 1

/* reinit_completion is exist */
#define HAVE_REINIT_COMPLETION 1

/* kernel export remove_from_page_cache */
/* #undef HAVE_REMOVE_FROM_PAGE_CACHE */

/* remove_proc_subtree is defined */
#define HAVE_REMOVE_PROC_SUBTREE 1

/* Have sa_spill_alloc in ZFS */
/* #undef HAVE_SA_SPILL_ALLOC */

/* super_operations.evict_inode() is exist in kernel */
#define HAVE_SBOPS_EVICT_INODE 1

/* kernel supports wrapped FS freeze functions */
#define HAVE_SB_START_WRITE 1

/* Define to 1 if you have the <sched.h> header file. */
#define HAVE_SCHED_H 1

/* linux/sched header directory exist */
#define HAVE_SCHED_HEADERS 1

/* security_dentry_init_security' is defined */
#define HAVE_SECURITY_DENTRY_INIT_SECURITY 1

/* security_inode_init_security takes a callback to set xattrs */
#define HAVE_SECURITY_IINITSEC_CALLBACK 1

/* security_inode_init_security takes a 'struct qstr' parameter */
/* #undef HAVE_SECURITY_IINITSEC_QSTR */

/* support for selinux */
#define HAVE_SELINUX 1

/* Define to 1 if you have the <selinux/selinux.h> header file. */
#define HAVE_SELINUX_SELINUX_H 1

/* support server */
/* #undef HAVE_SERVER_SUPPORT */

/* Define to 1 if you have the `setns' function. */
#define HAVE_SETNS 1

/* Define this if the Kerberos GSS library supports
   gss_krb5_set_allowable_enctypes */
/* #undef HAVE_SET_ALLOWABLE_ENCTYPES */

/* shrinker has count_objects member */
#define HAVE_SHRINKER_COUNT 1

/* shrinker want self pointer in handler */
/* #undef HAVE_SHRINKER_WANT_SHRINK_PTR */

/* shrink_control is present */
#define HAVE_SHRINK_CONTROL 1

/* simple_setattr is exported by the kernel */
#define HAVE_SIMPLE_SETATTR 1

/* sk_data_ready uses only one argument */
#define HAVE_SK_DATA_READY_ONE_ARG 1

/* kernel has sk_sleep */
#define HAVE_SK_SLEEP 1

/* sock_alloc_file is exported */
/* #undef HAVE_SOCK_ALLOC_FILE */

/* sock_alloc_file takes 3 arguments */
#define HAVE_SOCK_ALLOC_FILE_3ARGS 1

/* sock_create_kern use net as first parameter */
#define HAVE_SOCK_CREATE_KERN_USE_NET 1

/* Have spa_maxblocksize in ZFS */
/* #undef HAVE_SPA_MAXBLOCKSIZE */

/* spinlock_t is defined */
/* #undef HAVE_SPINLOCK_T */

/* struct stacktrace_ops exists */
/* #undef HAVE_STACKTRACE_OPS */

/* stacktrace_ops.warning is exist */
/* #undef HAVE_STACKTRACE_WARNING */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
/* #undef HAVE_STRLCAT */

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the `strnlen' function. */
#define HAVE_STRNLEN 1

/* struct posix_acl_xattr_{header,entry} defined */
#define HAVE_STRUCT_POSIX_ACL_XATTR 1

/* submit_bio takes two arguments */
/* #undef HAVE_SUBMIT_BIO_2ARGS */

/* sunrpc_cache_pipe_upcall takes 3 args */
/* #undef HAVE_SUNRPC_UPCALL_HAS_3ARGS */

/* super_operations use dentry as parameter */
#define HAVE_SUPEROPS_USE_DENTRY 1

/* 'super_setup_bdi_name' is available */
#define HAVE_SUPER_SETUP_BDI_NAME 1

/* symlink inode operations need struct nameidata argument */
/* #undef HAVE_SYMLINK_OPS_USE_NAMEIDATA */

/* new_sync_[read|write] is exported by the kernel */
/* #undef HAVE_SYNC_READ_WRITE */

/* ctl_table has ctl_name field */
/* #undef HAVE_SYSCTL_CTLNAME */

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have <sys/quota.h>. */
#define HAVE_SYS_QUOTA_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* tcp_sendpage use socket as first parameter */
/* #undef HAVE_TCP_SENDPAGE_USE_SOCKET */

/* 'struct timespec64' is available */
#define HAVE_TIMESPEC64 1

/* 'timespec64_sub' is available */
#define HAVE_TIMESPEC64_SUB 1

/* 'timespec64_to_ktime' is available */
#define HAVE_TIMESPEC64_TO_KTIME 1

/* topology_sibling_cpumask is available */
#define HAVE_TOPOLOGY_SIBLING_CPUMASK 1

/* kernel export truncate_complete_page */
/* #undef HAVE_TRUNCATE_COMPLETE_PAGE */

/* kernel has truncate_inode_pages_final */
#define HAVE_TRUNCATE_INODE_PAGES_FINAL 1

/* uidgid.h is present */
#define HAVE_UIDGID_HEADER 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* xattr_handler has a name member */
#define HAVE_XATTR_HANDLER_NAME 1

/* kernel has vfs_rename with 5 args */
/* #undef HAVE_VFS_RENAME_5ARGS */

/* kernel has vfs_rename with 6 args */
#define HAVE_VFS_RENAME_6ARGS 1

/* '__vfs_setxattr is available */
#define HAVE_VFS_SETXATTR 1

/* kernel has vfs_unlink with 3 args */
#define HAVE_VFS_UNLINK_3ARGS 1

/* virtual_address has been replaced by address field */
#define HAVE_VM_FAULT_ADDRESS 1

/* 'struct vm_operations' remove struct vm_area_struct argument */
#define HAVE_VM_OPS_USE_VM_FAULT_ONLY 1

/* 'wait_queue_entry_t' is available */
#define HAVE_WAIT_QUEUE_ENTRY 1

/* flags field exist */
#define HAVE_XATTR_HANDLER_FLAGS 1

/* needs inode parameter */
#define HAVE_XATTR_HANDLER_INODE_PARAM 1

/* handler pointer is parameter */
/* #undef HAVE_XATTR_HANDLER_SIMPLIFIED */

/* Have zap_add_by_dnode() in ZFS */
/* #undef HAVE_ZAP_ADD_BY_DNODE */

/* Have zap_lookup_by_dnode() in ZFS */
/* #undef HAVE_ZAP_LOOKUP_BY_DNODE */

/* Have zap_remove_by_dnode() in ZFS */
/* #undef HAVE_ZAP_REMOVE_ADD_BY_DNODE */

/* Enable zfs osd */
/* #undef HAVE_ZFS_OSD */

/* __add_wait_queue_exclusive exists */
/* #undef HAVE___ADD_WAIT_QUEUE_EXCLUSIVE */

/* ext4_journal_start takes 3 arguments */
/* #undef JOURNAL_START_HAS_3ARGS */

/* Define this as the Kerberos version number */
/* #undef KRB5_VERSION */

/* enable libcfs LASSERT, LASSERTF */
#define LIBCFS_DEBUG 1

/* use dumplog on panic */
/* #undef LNET_DUMP_ON_PANIC */

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Fourth number in the Lustre version */
#define LUSTRE_FIX 0

/* First number in the Lustre version */
#define LUSTRE_MAJOR 2

/* Second number in the Lustre version */
#define LUSTRE_MINOR 10

/* Third number in the Lustre version */
#define LUSTRE_PATCH 5

/* A copy of PACKAGE_VERSION */
#define LUSTRE_VERSION_STRING "2.10.5"

/* maximum number of MDS threads */
/* #undef MDS_MAX_THREADS */

/* Report minimum OST free space */
/* #undef MIN_DF */

/* name of ldiskfs mkfs program */
#define MKE2FS "mke2fs"

/* need pclmulqdq based crc32c */
/* #undef NEED_CRC32C_ACCEL */

/* need pclmulqdq based crc32 */
/* #undef NEED_CRC32_ACCEL */

/* 'ktime_get_real_ns' is not available */
/* #undef NEED_KTIME_GET_REAL_NS */

/* enable nodemap proc debug support */
/* #undef NODEMAP_PROC_DEBUG */

/* Name of package */
#define PACKAGE "lustre"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://jira.hpdd.intel.com/"

/* Define to the full name of this package. */
#define PACKAGE_NAME "Lustre"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "Lustre 2.10.5"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "lustre"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.10.5"

/* name of parallel fsck program */
#define PFSCK "fsck"

/* enable randomly alloc failure */
#define RANDOM_FAIL_ALLOC 1

/* The size of `unsigned long long', as computed by sizeof. */
#define SIZEOF_UNSIGNED_LONG_LONG 8

/* use tunable backoff TCP */
/* #undef SOCKNAL_BACKOFF */

/* tunable backoff TCP in ms */
/* #undef SOCKNAL_BACKOFF_MS */

/* 'struct stacktrace_ops' address function returns an int */
/* #undef STACKTRACE_OPS_ADDRESS_RETURN_INT */

/* 'struct stacktrace_ops' has 'walk_stack' field */
/* #undef STACKTRACE_OPS_HAVE_WALK_STACK */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* name of ldiskfs tune program */
#define TUNE2FS "tune2fs"

/* Define this if the private function, gss_krb5_cache_name, must be used to
   tell the Kerberos library which credentials cache to use. Otherwise, this
   is done by setting the KRB5CCNAME environment variable */
/* #undef USE_GSS_KRB5_CCACHE_NAME */

/* Write when Checking Health */
/* #undef USE_HEALTH_CHECK_WRITE */

/* enable lu_ref reference tracking code */
/* #undef USE_LU_REF */

/* Version number of package */
#define VERSION "2.10.5"

/* zfs fix version */
/* #undef ZFS_FIX */

/* zfs major version */
/* #undef ZFS_MAJOR */

/* zfs minor version */
/* #undef ZFS_MINOR */

/* zfs patch version */
/* #undef ZFS_PATCH */
