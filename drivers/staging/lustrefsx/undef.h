
/* enable libcfs CDEBUG, CWARN */
#undef CDEBUG_ENABLED

/* enable libcfs ENTRY/EXIT */
#undef CDEBUG_ENTRY_EXIT

/* enable page state tracking code */
#undef CONFIG_DEBUG_PAGESTATE_TRACKING

/* enable encryption for ldiskfs */
#undef CONFIG_LDISKFS_FS_ENCRYPTION

/* posix acls for ldiskfs */
#undef CONFIG_LDISKFS_FS_POSIX_ACL

/* enable rw access for ldiskfs */
#undef CONFIG_LDISKFS_FS_RW

/* fs security for ldiskfs */
#undef CONFIG_LDISKFS_FS_SECURITY

/* extened attributes for ldiskfs */
#undef CONFIG_LDISKFS_FS_XATTR

/* enable invariant checking */
#undef CONFIG_LUSTRE_DEBUG_EXPENSIVE_CHECK

/* kernel has cpu affinity support */
#undef CPU_AFFINITY

/* both i_dentry/d_alias uses list */
#undef DATA_FOR_LLITE_IS_LIST

/* name of ldiskfs debug program */
#undef DEBUGFS

/* name of ldiskfs dump program */
#undef DUMPE2FS

/* name of ldiskfs fsck program */
#undef E2FSCK

/* name of ldiskfs e2fsprogs package */
#undef E2FSPROGS

/* name of ldiskfs label program */
#undef E2LABEL

/* do data checksums */
#undef ENABLE_CHECKSUM

/* enable flock by default */
#undef ENABLE_FLOCK

/* Use the Pinger */
#undef ENABLE_PINGER

/* aes-sha2 is supported by krb5 */
#undef HAVE_AES_SHA2_SUPPORT

/* Define to 1 if you have the <asm/types.h> header file. */
#undef HAVE_ASM_TYPES_H

/* backing_dev_info exist */
#undef HAVE_BACKING_DEV_INFO

/* BDI_CAP_MAP_COPY exist */
#undef HAVE_BDI_CAP_MAP_COPY

/* bio_endio takes only one argument */
#undef HAVE_BIO_ENDIO_USES_ONE_ARG

/* bio_end_sector is defined */
#undef HAVE_BIO_END_SECTOR

/* 'bio_integrity_enabled' is available */
#undef HAVE_BIO_INTEGRITY_ENABLED

/* kernel has bio_integrity_prep_fn */
#undef HAVE_BIO_INTEGRITY_PREP_FN

/* bio_integrity_payload.bip_iter exist */
#undef HAVE_BIP_ITER_BIO_INTEGRITY_PAYLOAD

/* 'bi_bdev' is available */
#undef HAVE_BI_BDEV

/* struct bio has bi_cnt */
#undef HAVE_BI_CNT

/* struct bio has bi_rw */
#undef HAVE_BI_RW

/* 'bi_status' is available */
#undef HAVE_BI_STATUS

/* blkdev_get_by_dev is exported by the kernel */
#undef HAVE_BLKDEV_GET_BY_DEV

/* Define to 1 if you have the <blkid/blkid.h> header file. */
#undef HAVE_BLKID_BLKID_H

/* blk_plug struct exists */
#undef HAVE_BLK_PLUG

/* blk_queue_max_segments is defined */
#undef HAVE_BLK_QUEUE_MAX_SEGMENTS

/* kernel hash_64() is broken */
#undef HAVE_BROKEN_HASH_64

/* kernel has struct bvec_iter */
#undef HAVE_BVEC_ITER

/* struct cache_detail has writers */
#undef HAVE_CACHE_DETAIL_WRITERS

/* if cache_detail->hash_lock is a spinlock */
#undef HAVE_CACHE_HASH_SPINLOCK

/* cache_head has hlist cache_list */
#undef HAVE_CACHE_HEAD_HLIST

/* have cache_register */
#undef HAVE_CACHE_REGISTER

/* cancel_dirty_page is still available */
#undef HAVE_CANCEL_DIRTY_PAGE

/* kernel has clean_bdev_aliases */
#undef HAVE_CLEAN_BDEV_ALIASES

/* 'clear_and_wake_up_bit' is available */
#undef HAVE_CLEAR_AND_WAKE_UP_BIT

/* have clear_inode */
#undef HAVE_CLEAR_INODE

/* compat rdma found */
#undef HAVE_COMPAT_RDMA

/* 'cpu_read_lock' exist */
#undef HAVE_CPUS_READ_LOCK

/* kernel compiled with CRC32 functions */
#undef HAVE_CRC32

/* crypto hash helper functions are available */
#undef HAVE_CRYPTO_HASH_HELPERS

/* 'CRYPTO_MAX_ALG_NAME' is 128 */
#undef HAVE_CRYPTO_MAX_ALG_NAME_128

/* current_time() has replaced CURRENT_TIME */
#undef HAVE_CURRENT_TIME

/* dcache_lock is exist */
#undef HAVE_DCACHE_LOCK

/* kernel export delete_from_page_cache */
#undef HAVE_DELETE_FROM_PAGE_CACHE

/* dentry.d_child exist */
#undef HAVE_DENTRY_D_CHILD

/* hlist dentry.d_u.d_alias exist */
#undef HAVE_DENTRY_D_U_D_ALIAS

/* dentry_open uses struct path as first argument */
#undef HAVE_DENTRY_OPEN_USE_PATH

/* DES3 enctype is supported by krb5 */
#undef HAVE_DES3_SUPPORT

/* direct_IO need 2 arguments */
#undef HAVE_DIRECTIO_2ARGS

/* direct IO uses iov_iter */
#undef HAVE_DIRECTIO_ITER

/* dirty_inode super_operation takes flag */
#undef HAVE_DIRTY_INODE_HAS_FLAG

/* dir_context exist */
#undef HAVE_DIR_CONTEXT

/* Define to 1 if you have the <dlfcn.h> header file. */
#undef HAVE_DLFCN_H

/* Have dmu_object_alloc_dnsize in ZFS */
#undef HAVE_DMU_OBJECT_ALLOC_DNSIZE

/* Have dmu_objset_disown() with 3 args */
#undef HAVE_DMU_OBJSET_DISOWN_3ARG

/* Have dmu_objset_own() with 6 args */
#undef HAVE_DMU_OBJSET_OWN_6ARG

/* Have 6 argument dmu_pretch in ZFS */
#undef HAVE_DMU_PREFETCH_6ARG

/* Have dmu_read_by_dnode() in ZFS */
#undef HAVE_DMU_READ_BY_DNODE

/* Have dmu_tx_hold_write_by_dnode() in ZFS */
#undef HAVE_DMU_TX_HOLD_WRITE_BY_DNODE

/* Have dmu_tx_hold_zap_by_dnode() in ZFS */
#undef HAVE_DMU_TX_HOLD_ZAP_BY_DNODE

/* Have dmu_tx_mark_netfree */
#undef HAVE_DMU_TX_MARK_NETFREE

/* Have native dnode accounting in ZFS */
#undef HAVE_DMU_USEROBJ_ACCOUNTING

/* Have dmu_write_by_dnode() in ZFS */
#undef HAVE_DMU_WRITE_BY_DNODE

/* quotactl_ops.set_dqblk takes struct fs_disk_quota */
#undef HAVE_DQUOT_FS_DISK_QUOTA

/* quotactl_ops.set_dqblk takes struct kqid */
#undef HAVE_DQUOT_KQID

/* quotactl_ops.set_dqblk takes struct qc_dqblk */
#undef HAVE_DQUOT_QC_DQBLK

/* dquot_suspend is defined */
#undef HAVE_DQUOT_SUSPEND

/* Have dsl_pool_config_enter/exit in ZFS */
#undef HAVE_DSL_POOL_CONFIG

/* Have dsl_sync_task_do_nowait in ZFS */
#undef HAVE_DSL_SYNC_TASK_DO_NOWAIT

/* dump_trace want address argument */
#undef HAVE_DUMP_TRACE_ADDRESS

/* d_compare need 4 arguments */
#undef HAVE_D_COMPARE_4ARGS

/* d_compare need 5 arguments */
#undef HAVE_D_COMPARE_5ARGS

/* d_compare need 7 arguments */
#undef HAVE_D_COMPARE_7ARGS

/* d_count exist */
#undef HAVE_D_COUNT

/* d_delete first parameter declared is not const */
#undef HAVE_D_DELETE_CONST

/* d_hash_and_lookup is exported by the kernel */
#undef HAVE_D_HASH_AND_LOOKUP

/* have d_make_root */
#undef HAVE_D_MAKE_ROOT

/* have parent inode as parameter */
#undef HAVE_ENCODE_FH_PARENT

/* Define to 1 if you have the <endian.h> header file. */
#undef HAVE_ENDIAN_H

/* Define to 1 if you have the <ext2fs/ext2fs.h> header file. */
#undef HAVE_EXT2FS_EXT2FS_H

/* ext4_bread takes 4 arguments */
#undef HAVE_EXT4_BREAD_4ARGS

/* i_dquot is in ext4_inode_info */
#undef HAVE_EXT4_INFO_DQUOT

/* ext4_free_blocks do not require struct buffer_head */
#undef HAVE_EXT_FREE_BLOCK_WITH_BUFFER_HEAD

/* Linux kernel has ext_pblock */
#undef HAVE_EXT_PBLOCK

/* file handle and related syscalls are supported */
#undef HAVE_FHANDLE_GLIBC_SUPPORT

/* kernel supports fhandles and related syscalls */
#undef HAVE_FHANDLE_SYSCALLS

/* kernel has file_dentry */
#undef HAVE_FILE_DENTRY

/* file_operations.fsync takes 2 arguments */
#undef HAVE_FILE_FSYNC_2ARGS

/* file_operations.fsync takes 4 arguments */
#undef HAVE_FILE_FSYNC_4ARGS

/* struct file has member f_inode */
#undef HAVE_FILE_F_INODE

/* file_inode() has been defined */
#undef HAVE_FILE_INODE

/* generic_file_llseek_size is exported by the kernel */
#undef HAVE_FILE_LLSEEK_SIZE

/* kernel has generic_file_llseek_size with 5 args */
#undef HAVE_FILE_LLSEEK_SIZE_5ARGS

/* file_operations.[read|write]_iter functions exist */
#undef HAVE_FILE_OPERATIONS_READ_WRITE_ITER

/* filldir_t needs struct dir_context as argument */
#undef HAVE_FILLDIR_USE_CTX

/* FMR pool API is available */
#undef HAVE_FMR_POOL_API

/* fpu/api.h is present */
#undef HAVE_FPU_API_HEADER

/* struct file_system_type has mount field */
#undef HAVE_FSTYPE_MOUNT

/* fs_struct.lock use rwlock */
#undef HAVE_FS_STRUCT_RWLOCK

/* fs_struct use seqcount */
#undef HAVE_FS_STRUCT_SEQCOUNT

/* full_name_hash need 3 arguments */
#undef HAVE_FULL_NAME_HASH_3ARGS

/* generic_permission taken 2 arguments */
#undef HAVE_GENERIC_PERMISSION_2ARGS

/* generic_permission taken 4 arguments */
#undef HAVE_GENERIC_PERMISSION_4ARGS

/* generic_write_sync need 2 arguments */
#undef HAVE_GENERIC_WRITE_SYNC_2ARGS

/* Define to 1 if you have the `gethostbyname' function. */
#undef HAVE_GETHOSTBYNAME

/* 'get_acl' has a rcu argument */
#undef HAVE_GET_ACL_RCU_ARG

/* get_request_key_auth() is available */
#undef HAVE_GET_REQUEST_KEY_AUTH

/* get_user_pages takes 6 arguments */
#undef HAVE_GET_USER_PAGES_6ARG

/* get_user_pages takes gup_flags in arguments */
#undef HAVE_GET_USER_PAGES_GUP_FLAGS

/* struct group_info has member gid */
#undef HAVE_GROUP_INFO_GID

/* Define this is if you enable gss */
#undef HAVE_GSS

/* Define this if you enable gss keyring backend */
#undef HAVE_GSS_KEYRING

/* Define this if the Kerberos GSS library supports gss_krb5_ccache_name */
#undef HAVE_GSS_KRB5_CCACHE_NAME

/* '__rhashtable_insert_fast()' returns int */
#undef HAVE_HASHTABLE_INSERT_FAST_RETURN_INT

/* Define this if you have Heimdal Kerberos libraries */
#undef HAVE_HEIMDAL

/* hlist_add_after is available */
#undef HAVE_HLIST_ADD_AFTER

/* hlist_for_each_entry has 3 args */
#undef HAVE_HLIST_FOR_EACH_3ARG

/* hotplug state machine is supported */
#undef HAVE_HOTPLUG_STATE_MACHINE

/* ib_alloc_fast_reg_mr is defined */
#undef HAVE_IB_ALLOC_FAST_REG_MR

/* ib_alloc_pd has 2 arguments */
#undef HAVE_IB_ALLOC_PD_2ARGS

/* struct ib_cq_init_attr is used by ib_create_cq */
#undef HAVE_IB_CQ_INIT_ATTR

/* struct ib_device.attrs is defined */
#undef HAVE_IB_DEVICE_ATTRS

/* if struct ib_device_ops is defined */
#undef HAVE_IB_DEVICE_OPS

/* ib_get_dma_mr is defined */
#undef HAVE_IB_GET_DMA_MR

/* function ib_inc_rkey exist */
#undef HAVE_IB_INC_RKEY

/* ib_map_mr_sg exists */
#undef HAVE_IB_MAP_MR_SG

/* ib_map_mr_sg has 5 arguments */
#undef HAVE_IB_MAP_MR_SG_5ARGS

/* ib_post_send and ib_post_recv have const parameters */
#undef HAVE_IB_POST_SEND_RECV_CONST

/* struct ib_rdma_wr is defined */
#undef HAVE_IB_RDMA_WR

/* if ib_sg_dma_address wrapper exists */
#undef HAVE_IB_SG_DMA_ADDRESS

/* INIT_LIST_HEAD_RCU exists */
#undef HAVE_INIT_LIST_HEAD_RCU

/* inode_operations .getattr member function can gather advance stats */
#undef HAVE_INODEOPS_ENHANCED_GETATTR

/* inode_operations has .truncate member function */
#undef HAVE_INODEOPS_TRUNCATE

/* inode_operations use umode_t as parameter */
#undef HAVE_INODEOPS_USE_UMODE_T

/* inode->i_alloc_sem is killed and use inode_dio_wait */
#undef HAVE_INODE_DIO_WAIT

/* inode.i_rcu exists */
#undef HAVE_INODE_I_RCU

/* inode_lock is defined */
#undef HAVE_INODE_LOCK

/* inode_owner_or_capable exist */
#undef HAVE_INODE_OWNER_OR_CAPABLE

/* inode_operations->permission has two args */
#undef HAVE_INODE_PERMISION_2ARGS

/* inode times are using timespec64 */
#undef HAVE_INODE_TIMESPEC64

/* blk_integrity.interval exist */
#undef HAVE_INTERVAL_BLK_INTEGRITY

/* blk_integrity.interval_exp exist */
#undef HAVE_INTERVAL_EXP_BLK_INTEGRITY

/* Define to 1 if you have the <inttypes.h> header file. */
#undef HAVE_INTTYPES_H

/* address_space_operations.invalidatepage needs 3 arguments */
#undef HAVE_INVALIDATE_RANGE

/* have in_compat_syscall */
#undef HAVE_IN_COMPAT_SYSCALL

/* 'in_dev_for_each_ifa_rtnl' is defined */
#undef HAVE_IN_DEV_FOR_EACH_IFA_RTNL

/* inode_operations->rename need flags as argument */
#undef HAVE_IOPS_RENAME_WITH_FLAGS

/* have iop atomic_open */
#undef HAVE_IOP_ATOMIC_OPEN

/* generic_readlink has been removed */
#undef HAVE_IOP_GENERIC_READLINK

/* inode_operations has .get_acl member function */
#undef HAVE_IOP_GET_ACL

/* have iop get_link */
#undef HAVE_IOP_GET_LINK

/* inode_operations has .set_acl member function */
#undef HAVE_IOP_SET_ACL

/* inode_operations has {get,set,remove}xattr members */
#undef HAVE_IOP_XATTR

/* if iov_iter has member iter_type */
#undef HAVE_IOV_ITER_HAS_TYPE_MEMBER

/* iov_iter_init handles directional tag */
#undef HAVE_IOV_ITER_INIT_DIRECTION

/* iov_iter_rw exist */
#undef HAVE_IOV_ITER_RW

/* iov_iter_truncate exists */
#undef HAVE_IOV_ITER_TRUNCATE

/* if iov_iter_type exists */
#undef HAVE_IOV_ITER_TYPE

/* is_root_inode defined */
#undef HAVE_IS_ROOT_INODE

/* is_sxid is defined */
#undef HAVE_IS_SXID

/* 'iterate_shared' is available */
#undef HAVE_ITERATE_SHARED

/* struct address_space has i_pages */
#undef HAVE_I_PAGES

/* i_uid_read is present */
#undef HAVE_I_UID_READ

/* kallsyms_lookup_name is exported by kernel */
#undef HAVE_KALLSYMS_LOOKUP_NAME

/* kernel_locked is defined */
#undef HAVE_KERNEL_LOCKED

/* 'kernel_param_[un]lock' is available */
#undef HAVE_KERNEL_PARAM_LOCK

/* 'struct kernel_param_ops' is available */
#undef HAVE_KERNEL_PARAM_OPS

/* kernel_setsockopt still in use */
#undef HAVE_KERNEL_SETSOCKOPT

/* 'struct sock' accept function requires bool argument */
#undef HAVE_KERN_SOCK_ACCEPT_FLAG_ARG

/* 'getname' has two args */
#undef HAVE_KERN_SOCK_GETNAME_2ARGS

/* struct key_match_data exist */
#undef HAVE_KEY_MATCH_DATA

/* payload.data is an array */
#undef HAVE_KEY_PAYLOAD_DATA_ARRAY

/* key_type->instantiate has two args */
#undef HAVE_KEY_TYPE_INSTANTIATE_2ARGS

/* key.usage is of type refcount_t */
#undef HAVE_KEY_USAGE_REFCOUNT

/* ki_left exist */
#undef HAVE_KIOCB_KI_LEFT

/* ki_nbytes field exist */
#undef HAVE_KI_NBYTES

/* have kmap_atomic has only 1 argument */
#undef HAVE_KMAP_ATOMIC_HAS_1ARG

/* kmap_to_page is exported by the kernel */
#undef HAVE_KMAP_TO_PAGE

/* Define this if you have MIT Kerberos libraries */
#undef HAVE_KRB5

/* Define this if the function krb5int_derive_key is available */
#undef HAVE_KRB5INT_DERIVE_KEY

/* Define this if the function krb5_derive_key is available */
#undef HAVE_KRB5_DERIVE_KEY

/* Define this if the function krb5_get_error_message is available */
#undef HAVE_KRB5_GET_ERROR_MESSAGE

/* Define this if the function krb5_get_init_creds_opt_set_addressless is
   available */
#undef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_ADDRESSLESS

/* kset_find_obj is exported by the kernel */
#undef HAVE_KSET_FIND_OBJ

/* kernel has kstrtobool_from_user */
#undef HAVE_KSTRTOBOOL_FROM_USER

/* kernel has kstrtoul */
#undef HAVE_KSTRTOUL

/* kthread_worker found */
#undef HAVE_KTHREAD_WORK

/* ktime_add is available */
#undef HAVE_KTIME_ADD

/* ktime_after is available */
#undef HAVE_KTIME_AFTER

/* ktime_before is available */
#undef HAVE_KTIME_BEFORE

/* ktime_compare is available */
#undef HAVE_KTIME_COMPARE

/* 'ktime_get_real_seconds' is available */
#undef HAVE_KTIME_GET_REAL_SECONDS

/* 'ktime_get_real_ts64' is available */
#undef HAVE_KTIME_GET_REAL_TS64

/* 'ktime_get_seconds' is available */
#undef HAVE_KTIME_GET_SECONDS

/* 'ktime_get_ts64' is available */
#undef HAVE_KTIME_GET_TS64

/* 'ktime_ms_delta' is available */
#undef HAVE_KTIME_MS_DELTA

/* 'ktime_to_timespec64' is available */
#undef HAVE_KTIME_TO_TIMESPEC64

/* enable use of ldiskfsprogs package */
#undef HAVE_LDISKFSPROGS

/* kernel has ext4_map_blocks */
#undef HAVE_LDISKFS_MAP_BLOCKS

/* Enable ldiskfs osd */
#undef HAVE_LDISKFS_OSD

/* libefence support is requested */
#undef HAVE_LIBEFENCE

/* Define to 1 if you have the `keyutils' library (-lkeyutils). */
#undef HAVE_LIBKEYUTILS

/* build with libmount */
#undef HAVE_LIBMOUNT

/* use libpthread for libcfs library */
#undef HAVE_LIBPTHREAD

/* readline library is available */
#undef HAVE_LIBREADLINE

/* linux/rhashtable.h is present */
#undef HAVE_LINUX_RHASHTABLE_H

/* if linux/selinux.h exists */
#undef HAVE_LINUX_SELINUX_IS_ENABLED

/* linux/stdarg.h is present */
#undef HAVE_LINUX_STDARG_HEADER

/* lock_manager_operations has lm_compare_owner */
#undef HAVE_LM_COMPARE_OWNER

/* lock-manager ops renamed to lm_xxx */
#undef HAVE_LM_XXX_LOCK_MANAGER_OPS

/* kernel has locks_lock_file_wait */
#undef HAVE_LOCKS_LOCK_FILE_WAIT

/* lookup_user_key() is available */
#undef HAVE_LOOKUP_USER_KEY

/* kernel has LOOP_CTL_GET_FREE */
#undef HAVE_LOOP_CTL_GET_FREE

/* Enable lru resize support */
#undef HAVE_LRU_RESIZE_SUPPORT

/* Define this if the Kerberos GSS library supports
   gss_krb5_export_lucid_sec_context */
#undef HAVE_LUCID_CONTEXT_SUPPORT

/* Define to 1 if you have the <memory.h> header file. */
#undef HAVE_MEMORY_H

/* address_space_operations.migratepage has 4 args */
#undef HAVE_MIGRATEPAGE_4ARGS

/* kernel has include/linux/migrate.h */
#undef HAVE_MIGRATE_H

/* kernel has include/linux/migrate_mode.h */
#undef HAVE_MIGRATE_MODE_H

/* mmap_lock API is available. */
#undef HAVE_MMAP_LOCK

/* kernel module loading is possible */
#undef HAVE_MODULE_LOADING_SUPPORT

/* locking module param is supported */
#undef HAVE_MODULE_PARAM_LOCKING

/* Define to 1 if you have the `name_to_handle_at' function. */
#undef HAVE_NAME_TO_HANDLE_AT

/* Define to 1 if you have the <netdb.h> header file. */
#undef HAVE_NETDB_H

/* cancel_dirty_page with one arguement is available */
#undef HAVE_NEW_CANCEL_DIRTY_PAGE

/* DEFINE_TIMER uses only 2 arguements */
#undef HAVE_NEW_DEFINE_TIMER

/* 'kernel_write' aligns with read/write helpers */
#undef HAVE_NEW_KERNEL_WRITE

/* NR_UNSTABLE_NFS is still in use. */
#undef HAVE_NR_UNSTABLE_NFS

/* ns_to_timespec64() is available */
#undef HAVE_NS_TO_TIMESPEC64

/* with oldsize */
#undef HAVE_OLDSIZE_TRUNCATE_PAGECACHE

/* openssl-devel is present */
#undef HAVE_OPENSSL_GETSEPOL

/* OpenSSL HMAC functions needed for SSK */
#undef HAVE_OPENSSL_SSK

/* 'pagevec_init' takes one parameter */
#undef HAVE_PAGEVEC_INIT_ONE_PARAM

/* linux/panic_notifier.h is present */
#undef HAVE_PANIC_NOTIFIER_H

/* 'param_set_uint_minmax' is available */
#undef HAVE_PARAM_SET_UINT_MINMAX

/* have PCLMULQDQ instruction */
#undef HAVE_PCLMULQDQ

/* percpu_counter_init uses GFP_* flag */
#undef HAVE_PERCPU_COUNTER_INIT_GFP_FLAG

/* 'struct nsproxy' has 'pid_ns_for_children' */
#undef HAVE_PID_NS_FOR_CHILDREN

/* posix_acl_to_xattr takes struct user_namespace */
#undef HAVE_POSIXACL_USER_NS

/* 'posix_acl_update_mode' is available */
#undef HAVE_POSIX_ACL_UPDATE_MODE

/* posix_acl_valid takes struct user_namespace */
#undef HAVE_POSIX_ACL_VALID_USER_NS

/* 'prepare_to_wait_event' is available */
#undef HAVE_PREPARE_TO_WAIT_EVENT

/* struct proc_ops exists */
#undef HAVE_PROC_OPS

/* proc_remove is defined */
#undef HAVE_PROC_REMOVE

/* get_projid function exists */
#undef HAVE_PROJECT_QUOTA

/* inode->i_nlink is protected from direct modification */
#undef HAVE_PROTECT_I_NLINK

/* 'PTR_ERR_OR_ZERO' exist */
#undef HAVE_PTR_ERR_OR_ZERO

/* have quota64 */
#undef HAVE_QUOTA64

/* radix_tree_exceptional_entry exist */
#undef HAVE_RADIX_EXCEPTION_ENTRY

/* rdma_connect_locked is defined */
#undef HAVE_RDMA_CONNECT_LOCKED

/* rdma_create_id wants 4 args */
#undef HAVE_RDMA_CREATE_ID_4ARG

/* rdma_create_id wants 5 args */
#undef HAVE_RDMA_CREATE_ID_5ARG

/* rdma_reject has 4 arguments */
#undef HAVE_RDMA_REJECT_4ARGS

/* kernel export remove_from_page_cache */
#undef HAVE_REMOVE_FROM_PAGE_CACHE

/* remove_proc_subtree is defined */
#undef HAVE_REMOVE_PROC_SUBTREE

/* rhashtable_lookup() is available */
#undef HAVE_RHASHTABLE_LOOKUP

/* rhashtable_lookup_get_insert_fast() is available */
#undef HAVE_RHASHTABLE_LOOKUP_GET_INSERT_FAST

/* struct rhltable exist */
#undef HAVE_RHLTABLE

/* save_stack_trace_tsk is exported */
#undef HAVE_SAVE_STACK_TRACE_TSK

/* Have sa_spill_alloc in ZFS */
#undef HAVE_SA_SPILL_ALLOC

/* super_operations.evict_inode() is exist in kernel */
#undef HAVE_SBOPS_EVICT_INODE

/* kernel supports wrapped FS freeze functions */
#undef HAVE_SB_START_WRITE

/* Define to 1 if you have the <sched.h> header file. */
#undef HAVE_SCHED_H

/* linux/sched header directory exist */
#undef HAVE_SCHED_HEADERS

/* security_dentry_init_security' is defined */
#undef HAVE_SECURITY_DENTRY_INIT_SECURITY

/* security_inode_init_security takes a callback to set xattrs */
#undef HAVE_SECURITY_IINITSEC_CALLBACK

/* security_inode_init_security takes a 'struct qstr' parameter */
#undef HAVE_SECURITY_IINITSEC_QSTR

/* security_inode_listsecurity() is available/exported */
#undef HAVE_SECURITY_INODE_LISTSECURITY

/* security_release_secctx has 1 arg. */
#undef HAVE_SEC_RELEASE_SECCTX_1ARG

/* support for selinux */
#undef HAVE_SELINUX

/* Define to 1 if you have the <selinux/selinux.h> header file. */
#undef HAVE_SELINUX_SELINUX_H

/* support server */
#undef HAVE_SERVER_SUPPORT

/* Define to 1 if you have the `setns' function. */
#undef HAVE_SETNS

/* Define this if the Kerberos GSS library supports
   gss_krb5_set_allowable_enctypes */
#undef HAVE_SET_ALLOWABLE_ENCTYPES

/* shrinker has count_objects member */
#undef HAVE_SHRINKER_COUNT

/* shrinker want self pointer in handler */
#undef HAVE_SHRINKER_WANT_SHRINK_PTR

/* shrink_control is present */
#undef HAVE_SHRINK_CONTROL

/* simple_setattr is exported by the kernel */
#undef HAVE_SIMPLE_SETATTR

/* sk_data_ready uses only one argument */
#undef HAVE_SK_DATA_READY_ONE_ARG

/* kernel has sk_sleep */
#undef HAVE_SK_SLEEP

/* sock_create_kern use net as first parameter */
#undef HAVE_SOCK_CREATE_KERN_USE_NET

/* Have spa_maxblocksize in ZFS */
#undef HAVE_SPA_MAXBLOCKSIZE

/* struct stacktrace_ops exists */
#undef HAVE_STACKTRACE_OPS

/* stacktrace_ops.warning is exist */
#undef HAVE_STACKTRACE_WARNING

/* Define to 1 if you have the <stdint.h> header file. */
#undef HAVE_STDINT_H

/* Define to 1 if you have the <stdlib.h> header file. */
#undef HAVE_STDLIB_H

/* stringhash.h is present */
#undef HAVE_STRINGHASH

/* Define to 1 if you have the <strings.h> header file. */
#undef HAVE_STRINGS_H

/* Define to 1 if you have the <string.h> header file. */
#undef HAVE_STRING_H

/* Define to 1 if you have the `strnlen' function. */
#undef HAVE_STRNLEN

/* struct posix_acl_xattr_{header,entry} defined */
#undef HAVE_STRUCT_POSIX_ACL_XATTR

/* submit_bio takes two arguments */
#undef HAVE_SUBMIT_BIO_2ARGS

/* sunrpc_cache_pipe_upcall takes 3 args */
#undef HAVE_SUNRPC_UPCALL_HAS_3ARGS

/* super_operations use dentry as parameter */
#undef HAVE_SUPEROPS_USE_DENTRY

/* 'super_setup_bdi_name' is available */
#undef HAVE_SUPER_SETUP_BDI_NAME

/* symlink inode operations need struct nameidata argument */
#undef HAVE_SYMLINK_OPS_USE_NAMEIDATA

/* new_sync_[read|write] is exported by the kernel */
#undef HAVE_SYNC_READ_WRITE

/* ctl_table has ctl_name field */
#undef HAVE_SYSCTL_CTLNAME

/* Define to 1 if you have <sys/quota.h>. */
#undef HAVE_SYS_QUOTA_H

/* Define to 1 if you have the <sys/stat.h> header file. */
#undef HAVE_SYS_STAT_H

/* Define to 1 if you have the <sys/types.h> header file. */
#undef HAVE_SYS_TYPES_H

/* task_is_running() is defined */
#undef HAVE_TASK_IS_RUNNING

/* tcp_sendpage use socket as first parameter */
#undef HAVE_TCP_SENDPAGE_USE_SOCKET

/* 'tcp_sock_set_keepidle()' exists */
#undef HAVE_TCP_SOCK_SET_KEEPIDLE

/* 'tcp_sock_set_nodelay()' exists */
#undef HAVE_TCP_SOCK_SET_NODELAY

/* timer_setup has replaced setup_timer */
#undef HAVE_TIMER_SETUP

/* 'struct timespec64' is available */
#undef HAVE_TIMESPEC64

/* 'timespec64_sub' is available */
#undef HAVE_TIMESPEC64_SUB

/* 'timespec64_to_ktime' is available */
#undef HAVE_TIMESPEC64_TO_KTIME

/* topology_sibling_cpumask is available */
#undef HAVE_TOPOLOGY_SIBLING_CPUMASK

/* if totalram_pages is a function */
#undef HAVE_TOTALRAM_PAGES_AS_FUNC

/* kernel export truncate_complete_page */
#undef HAVE_TRUNCATE_COMPLETE_PAGE

/* kernel has truncate_inode_pages_final */
#undef HAVE_TRUNCATE_INODE_PAGES_FINAL

/* if MS_RDONLY was moved to uapi/linux/mount.h */
#undef HAVE_UAPI_LINUX_MOUNT_H

/* uidgid.h is present */
#undef HAVE_UIDGID_HEADER

/* Define to 1 if you have the <unistd.h> header file. */
#undef HAVE_UNISTD_H

/* 'inode_operations' members have user namespace argument */
#undef HAVE_USER_NAMESPACE_ARG

/* kernel has vfs_rename with 5 args */
#undef HAVE_VFS_RENAME_5ARGS

/* kernel has vfs_rename with 6 args */
#undef HAVE_VFS_RENAME_6ARGS

/* '__vfs_setxattr is available */
#undef HAVE_VFS_SETXATTR

/* kernel has vfs_unlink with 3 args */
#undef HAVE_VFS_UNLINK_3ARGS

/* __vmalloc only takes 2 args. */
#undef HAVE_VMALLOC_2ARGS

/* virtual_address has been replaced by address field */
#undef HAVE_VM_FAULT_ADDRESS

/* if VM_FAULT_RETRY is defined */
#undef HAVE_VM_FAULT_RETRY

/* if vm_fault_t type exists */
#undef HAVE_VM_FAULT_T

/* 'struct vm_operations' remove struct vm_area_struct argument */
#undef HAVE_VM_OPS_USE_VM_FAULT_ONLY

/* wait_bit.h is present */
#undef HAVE_WAIT_BIT_HEADER_H

/* 'wait_queue_entry_t' is available */
#undef HAVE_WAIT_QUEUE_ENTRY

/* linux wait_queue_head_t list_head is name head */
#undef HAVE_WAIT_QUEUE_ENTRY_LIST

/* 'wait_var_event' is available */
#undef HAVE_WAIT_VAR_EVENT

/* flags field exist */
#undef HAVE_XATTR_HANDLER_FLAGS

/* needs inode parameter */
#undef HAVE_XATTR_HANDLER_INODE_PARAM

/* xattr_handler has a name member */
#undef HAVE_XATTR_HANDLER_NAME

/* handler pointer is parameter */
#undef HAVE_XATTR_HANDLER_SIMPLIFIED

/* xa_is_value exist */
#undef HAVE_XA_IS_VALUE

/* Have zap_add_by_dnode() in ZFS */
#undef HAVE_ZAP_ADD_BY_DNODE

/* Have zap_lookup_by_dnode() in ZFS */
#undef HAVE_ZAP_LOOKUP_BY_DNODE

/* Have zap_remove_by_dnode() in ZFS */
#undef HAVE_ZAP_REMOVE_ADD_BY_DNODE

/* Have inode_timespec_t */
#undef HAVE_ZFS_INODE_TIMESPEC

/* Have multihost protection in ZFS */
#undef HAVE_ZFS_MULTIHOST

/* Enable zfs osd */
#undef HAVE_ZFS_OSD

/* Have zfs_refcount_add */
#undef HAVE_ZFS_REFCOUNT_ADD

/* __add_wait_queue_exclusive exists */
#undef HAVE___ADD_WAIT_QUEUE_EXCLUSIVE

/* ext4_journal_start takes 3 arguments */
#undef JOURNAL_START_HAS_3ARGS

/* Define this as the Kerberos version number */
#undef KRB5_VERSION

/* enable libcfs LASSERT, LASSERTF */
#undef LIBCFS_DEBUG

/* use dumplog on panic */
#undef LNET_DUMP_ON_PANIC

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#undef LT_OBJDIR

/* Fourth number in the Lustre version */
#undef LUSTRE_FIX

/* First number in the Lustre version */
#undef LUSTRE_MAJOR

/* Second number in the Lustre version */
#undef LUSTRE_MINOR

/* Third number in the Lustre version */
#undef LUSTRE_PATCH

/* A copy of PACKAGE_VERSION */
#undef LUSTRE_VERSION_STRING

/* maximum number of MDS threads */
#undef MDS_MAX_THREADS

/* Report minimum OST free space */
#undef MIN_DF

/* name of ldiskfs mkfs program */
#undef MKE2FS

/* need pclmulqdq based crc32c */
#undef NEED_CRC32C_ACCEL

/* need pclmulqdq based crc32 */
#undef NEED_CRC32_ACCEL

/* 'ktime_get_ns' is not available */
#undef NEED_KTIME_GET_NS

/* 'ktime_get_real_ns' is not available */
#undef NEED_KTIME_GET_REAL_NS

/* enable nodemap proc debug support */
#undef NODEMAP_PROC_DEBUG

/* Name of package */
#undef PACKAGE

/* Define to the address where bug reports for this package should be sent. */
#undef PACKAGE_BUGREPORT

/* Define to the full name of this package. */
#undef PACKAGE_NAME

/* Define to the full name and version of this package. */
#undef PACKAGE_STRING

/* Define to the one symbol short name of this package. */
#undef PACKAGE_TARNAME

/* Define to the home page for this package. */
#undef PACKAGE_URL

/* Define to the version of this package. */
#undef PACKAGE_VERSION

/* name of parallel fsck program */
#undef PFSCK

/* enable randomly alloc failure */
#undef RANDOM_FAIL_ALLOC

/* The size of `unsigned long long', as computed by sizeof. */
#undef SIZEOF_UNSIGNED_LONG_LONG

/* use tunable backoff TCP */
#undef SOCKNAL_BACKOFF

/* tunable backoff TCP in ms */
#undef SOCKNAL_BACKOFF_MS

/* 'struct stacktrace_ops' address function returns an int */
#undef STACKTRACE_OPS_ADDRESS_RETURN_INT

/* 'struct stacktrace_ops' has 'walk_stack' field */
#undef STACKTRACE_OPS_HAVE_WALK_STACK

/* Define to 1 if you have the ANSI C header files. */
#undef STDC_HEADERS

/* name of ldiskfs tune program */
#undef TUNE2FS

/* Define this if the private function, gss_krb5_cache_name, must be used to
   tell the Kerberos library which credentials cache to use. Otherwise, this
   is done by setting the KRB5CCNAME environment variable */
#undef USE_GSS_KRB5_CCACHE_NAME

/* Write when Checking Health */
#undef USE_HEALTH_CHECK_WRITE

/* enable lu_ref reference tracking code */
#undef USE_LU_REF

/* Version number of package */
#undef VERSION

/* zfs fix version */
#undef ZFS_FIX

/* zfs major version */
#undef ZFS_MAJOR

/* zfs minor version */
#undef ZFS_MINOR

/* zfs patch version */
#undef ZFS_PATCH
