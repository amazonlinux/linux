
/* enable libcfs CDEBUG, CWARN */
#undef CDEBUG_ENABLED

/* enable libcfs ENTRY/EXIT */
#undef CDEBUG_ENTRY_EXIT

/* enable page state tracking code */
#undef CONFIG_DEBUG_PAGESTATE_TRACKING

/* do data checksums */
#undef CONFIG_ENABLE_CHECKSUM

/* enable flock by default */
#undef CONFIG_ENABLE_FLOCK

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

/* embedded llcrypt */
#undef CONFIG_LL_ENCRYPTION

/* enable invariant checking */
#undef CONFIG_LUSTRE_DEBUG_EXPENSIVE_CHECK

/* enable lu_ref reference tracking code */
#undef CONFIG_LUSTRE_DEBUG_LU_REF

/* Use the Pinger */
#undef CONFIG_LUSTRE_FS_PINGER

/* Enable POSIX acl */
#undef CONFIG_LUSTRE_FS_POSIX_ACL

/* 'ClearPageError()' replacement */
#undef ClearPageError

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

/* filldir_t return type is bool or int */
#undef FILLDIR_TYPE

/* rhashtable_walk_init() has 3 args */
#undef HAVE_3ARG_RHASHTABLE_WALK_INIT

/* account_page_dirtied takes three arguments */
#undef HAVE_ACCOUNT_PAGE_DIRTIED_3ARGS

/* account_page_dirtied is exported */
#undef HAVE_ACCOUNT_PAGE_DIRTIED_EXPORT

/* 'get_acl' and 'set_acl' use dentry argument */
#undef HAVE_ACL_WITH_DENTRY

/* aes-sha2 is supported by krb5 */
#undef HAVE_AES_SHA2_SUPPORT

/* aio_complete defined */
#undef HAVE_AIO_COMPLETE

/* 'alloc_file_pseudo' exist */
#undef HAVE_ALLOC_FILE_PSEUDO

/* alloc_inode_sb() exists */
#undef HAVE_ALLOC_INODE_SB

/* struct address_space_operations() has migrate_folio() */
#undef HAVE_AOPS_MIGRATE_FOLIO

/* struct address_space_operations() has read_folio() */
#undef HAVE_AOPS_READ_FOLIO

/* struct address_space_operations() has release_folio() */
#undef HAVE_AOPS_RELEASE_FOLIO

/* Define to 1 if you have the <asm/types.h> header file. */
#undef HAVE_ASM_TYPES_H

/* backing_dev_info exist */
#undef HAVE_BACKING_DEV_INFO

/* BDI_CAP_MAP_COPY exist */
#undef HAVE_BDI_CAP_MAP_COPY

/* backing_dev_info has io_pages */
#undef HAVE_BDI_IO_PAGES

/* struct bio has bi_phys_segments member */
#undef HAVE_BIO_BI_PHYS_SEGMENTS

/* bio_endio takes only one argument */
#undef HAVE_BIO_ENDIO_USES_ONE_ARG

/* 'bio_integrity_enabled' is available */
#undef HAVE_BIO_INTEGRITY_ENABLED

/* kernel has bio_integrity_prep_fn */
#undef HAVE_BIO_INTEGRITY_PREP_FN

/* bio_integrity_prep_fn returns bool */
#undef HAVE_BIO_INTEGRITY_PREP_FN_RETURNS_BOOL

/* 'bio_set_dev' is available */
#undef HAVE_BIO_SET_DEV

/* bio_integrity_payload.bip_iter exist */
#undef HAVE_BIP_ITER_BIO_INTEGRITY_PAYLOAD

/* Linux bitmap can be allocated */
#undef HAVE_BITMAP_ALLOC

/* 'bi_bdev' is available */
#undef HAVE_BI_BDEV

/* struct bio has bi_opf */
#undef HAVE_BI_OPF

/* 'bi_status' is available */
#undef HAVE_BI_STATUS

/* kernel has struct blk_integrity_iter */
#undef HAVE_BLK_INTEGRITY_ITER

/* BLK_INTEGRITY_NOVERIFY is available */
#undef HAVE_BLK_INTEGRITY_NOVERIFY

/* kernel hash_64() is broken */
#undef HAVE_BROKEN_HASH_64

/* kernel has struct bvec_iter */
#undef HAVE_BVEC_ITER

/* if bvec_iter_all exists for multi-page bvec iternation */
#undef HAVE_BVEC_ITER_ALL

/* struct cache_detail has writers */
#undef HAVE_CACHE_DETAIL_WRITERS

/* if cache_detail->hash_lock is a spinlock */
#undef HAVE_CACHE_HASH_SPINLOCK

/* cache_head has hlist cache_list */
#undef HAVE_CACHE_HEAD_HLIST

/* crypto/internal/cipher.h is present */
#undef HAVE_CIPHER_H

/* kernel has clean_bdev_aliases */
#undef HAVE_CLEAN_BDEV_ALIASES

/* 'clear_and_wake_up_bit' is available */
#undef HAVE_CLEAR_AND_WAKE_UP_BIT

/* compat rdma found */
#undef HAVE_COMPAT_RDMA

/* struct ctl_table argument to proc_handler() is const */
#undef HAVE_CONST_CTR_TABLE

/* copy_file_range() is supported */
#undef HAVE_COPY_FILE_RANGE

/* 'cpus_read_lock' exist */
#undef HAVE_CPUS_READ_LOCK

/* crypto_alloc_skcipher is defined */
#undef HAVE_CRYPTO_ALLOC_SKCIPHER

/* crypto hash helper functions are available */
#undef HAVE_CRYPTO_HASH_HELPERS

/* 'CRYPTO_MAX_ALG_NAME' is 128 */
#undef HAVE_CRYPTO_MAX_ALG_NAME_128

/* crypto/sha2.h is present */
#undef HAVE_CRYPTO_SHA2_HEADER

/* current_time() has replaced CURRENT_TIME */
#undef HAVE_CURRENT_TIME

/* Have db_dirty_records list_t */
#undef HAVE_DB_DIRTY_RECORDS_LIST

/* default_file_splice_read is exported */
#undef HAVE_DEFAULT_FILE_SPLICE_READ_EXPORT

/* delete_from_page_cache is exported */
#undef HAVE_DELETE_FROM_PAGE_CACHE

/* dentry.d_child exist */
#undef HAVE_DENTRY_D_CHILD

/* sruct dentry has d_children member */
#undef HAVE_DENTRY_D_CHILDREN

/* list dentry.d_u.d_alias exist */
#undef HAVE_DENTRY_D_U_D_ALIAS

/* DES3 enctype is supported by krb5 */
#undef HAVE_DES3_SUPPORT

/* direct_IO has 2 arguments */
#undef HAVE_DIRECTIO_2ARGS

/* direct IO uses iov_iter */
#undef HAVE_DIRECTIO_ITER

/* address_spaace_operaions->dirty_folio() member exists */
#undef HAVE_DIRTY_FOLIO

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

/* Have dmu_offset_next() exported */
#undef HAVE_DMU_OFFSET_NEXT

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

/* down_write_killable function exists */
#undef HAVE_DOWN_WRITE_KILLABLE

/* quotactl_ops.set_dqblk takes struct kqid */
#undef HAVE_DQUOT_KQID

/* quotactl_ops.set_dqblk takes struct qc_dqblk */
#undef HAVE_DQUOT_QC_DQBLK

/* use mnt_idmap with dquot_transfer */
#undef HAVE_DQUOT_TRANSFER_WITH_USER_NS

/* Have dsl_pool_config_enter/exit in ZFS */
#undef HAVE_DSL_POOL_CONFIG

/* Have dsl_sync_task_do_nowait in ZFS */
#undef HAVE_DSL_SYNC_TASK_DO_NOWAIT

/* d_compare need 4 arguments */
#undef HAVE_D_COMPARE_4ARGS

/* d_compare need 5 arguments */
#undef HAVE_D_COMPARE_5ARGS

/* d_count exist */
#undef HAVE_D_COUNT

/* 'd_init' exists */
#undef HAVE_D_INIT

/* d_in_lookup is defined */
#undef HAVE_D_IN_LOOKUP

/* 'd_is_positive' is available */
#undef HAVE_D_IS_POSITIVE

/* Define to 1 if you have the <endian.h> header file. */
#undef HAVE_ENDIAN_H

/* enum iter_type has member 'iter_pipe' */
#undef HAVE_ENUM_ITER_PIPE

/* ethtool_link_settings is defined */
#undef HAVE_ETHTOOL_LINK_SETTINGS

/* Define to 1 if you have the <ext2fs/ext2fs.h> header file. */
#undef HAVE_EXT2FS_EXT2FS_H

/* ext4_bread takes 4 arguments */
#undef HAVE_EXT4_BREAD_4ARGS

/* ext4_(inc|dec)_count() has 2 arguments */
#undef HAVE_EXT4_INC_DEC_COUNT_2ARGS

/* i_dquot is in ext4_inode_info */
#undef HAVE_EXT4_INFO_DQUOT

/* ext4_free_blocks do not require struct buffer_head */
#undef HAVE_EXT_FREE_BLOCK_WITH_BUFFER_HEAD

/* file handle and related syscalls are supported */
#undef HAVE_FHANDLE_GLIBC_SUPPORT

/* union is unnamed */
#undef HAVE_FID2PATH_ANON_UNIONS

/* filemap_get_folios_contig() is available */
#undef HAVE_FILEMAP_GET_FOLIOS_CONTIG

/* 'filemap_splice_read' is available */
#undef HAVE_FILEMAP_SPLICE_READ

/* kernel has file_dentry */
#undef HAVE_FILE_DENTRY

/* file_operations.[read|write]_iter functions exist */
#undef HAVE_FILE_OPERATIONS_READ_WRITE_ITER

/* filldir_t needs struct dir_context as argument */
#undef HAVE_FILLDIR_USE_CTX

/* filldir_t needs struct dir_context and returns bool */
#undef HAVE_FILLDIR_USE_CTX_RETURN_BOOL

/* '__flush_workqueue(system_wq)' is available */
#undef HAVE_FLUSH___WORKQUEUE

/* FMR pool API is available */
#undef HAVE_FMR_POOL_API

/* 'struct folio_batch' is available */
#undef HAVE_FOLIO_BATCH

/* 'folio_batch_reinit' is available */
#undef HAVE_FOLIO_BATCH_REINIT

/* 'folio_mapcount()' is available */
#undef HAVE_FOLIO_MAPCOUNT

/* file_operations has iterate_shared */
#undef HAVE_FOP_ITERATE_SHARED

/* force_sig() has task parameter */
#undef HAVE_FORCE_SIG_WITH_TASK

/* 'struct fscrypt_digested_name' exists */
#undef HAVE_FSCRYPT_DIGESTED_NAME

/* embedded llcrypt uses llcrypt_dummy_context_enabled() */
#undef HAVE_FSCRYPT_DUMMY_CONTEXT_ENABLED

/* fscrypt_is_nokey_name() exists */
#undef HAVE_FSCRYPT_IS_NOKEY_NAME

/* full_name_hash need 3 arguments */
#undef HAVE_FULL_NAME_HASH_3ARGS

/* generic_error_remove_folio() exists */
#undef HAVE_GENERIC_ERROR_REMOVE_FOLIO

/* 'generic_fillattr()' has request_mask argument */
#undef HAVE_GENERIC_FILEATTR_HAS_MASK_ARG

/* generic_write_sync has 2 arguments */
#undef HAVE_GENERIC_WRITE_SYNC_2ARGS

/* struct genl_dumpit_info has family field */
#undef HAVE_GENL_DUMPIT_INFO

/* Define to 1 if you have the `gethostbyname' function. */
#undef HAVE_GETHOSTBYNAME

/* 'get_acl' has a rcu argument */
#undef HAVE_GET_ACL_RCU_ARG

/* 'get_expiry' takes time64_t */
#undef HAVE_GET_EXPIRY_2ARGS

/* get_inode_usage function exists */
#undef HAVE_GET_INODE_USAGE

/* get_random_[u32|u64] are available */
#undef HAVE_GET_RANDOM_U32_AND_U64

/* get_random_u32_below() is available */
#undef HAVE_GET_RANDOM_U32_BELOW

/* get_request_key_auth() is available */
#undef HAVE_GET_REQUEST_KEY_AUTH

/* get_user_pages takes 6 arguments */
#undef HAVE_GET_USER_PAGES_6ARG

/* get_user_pages takes gup_flags in arguments */
#undef HAVE_GET_USER_PAGES_GUP_FLAGS

/* get_user_pages removed 'vma' parameter */
#undef HAVE_GET_USER_PAGES_WITHOUT_VMA

/* glob_match() is available */
#undef HAVE_GLOB

/* grab_cache_page_write_begin() has flags argument */
#undef HAVE_GRAB_CACHE_PAGE_WRITE_BEGIN_WITH_FLAGS

/* struct group_info has member gid */
#undef HAVE_GROUP_INFO_GID

/* 'struct group_info.usage' is refcount_t */
#undef HAVE_GROUP_INFO_USAGE_AS_REFCOUNT

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

/* hotplug state machine is supported */
#undef HAVE_HOTPLUG_STATE_MACHINE

/* hypervisor_is_type function exists */
#undef HAVE_HYPERVISOR_IS_TYPE

/* ibdev_to_node() is defined */
#undef HAVE_IBDEV_TO_NODE

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

/* inode_operations .getattr member function can gather advance stats */
#undef HAVE_INODEOPS_ENHANCED_GETATTR

/* 'inode_get_ctime()' exists */
#undef HAVE_INODE_GET_CTIME

/* 'inode_get_mtime()' exists */
#undef HAVE_INODE_GET_MTIME_SEC

/* inode_lock is defined */
#undef HAVE_INODE_LOCK

/* inode times are using timespec64 */
#undef HAVE_INODE_TIMESPEC64

/* blk_integrity.interval exist */
#undef HAVE_INTERVAL_BLK_INTEGRITY

/* blk_integrity.interval_exp exist */
#undef HAVE_INTERVAL_EXP_BLK_INTEGRITY

/* interval trees use rb_tree_cached */
#undef HAVE_INTERVAL_TREE_CACHED

/* Define to 1 if you have the <inttypes.h> header file. */
#undef HAVE_INTTYPES_H

/* address_spaace_operaions->invalidate_folio() member exists */
#undef HAVE_INVALIDATE_FOLIO

/* address_space invalidate_lock member exists */
#undef HAVE_INVALIDATE_LOCK

/* address_space_operations.invalidatepage needs 3 arguments */
#undef HAVE_INVALIDATE_RANGE

/* have in_compat_syscall */
#undef HAVE_IN_COMPAT_SYSCALL

/* 'in_dev_for_each_ifa_rtnl' is defined */
#undef HAVE_IN_DEV_FOR_EACH_IFA_RTNL

/* inode_operations->rename need flags as argument */
#undef HAVE_IOPS_RENAME_WITH_FLAGS

/* generic_readlink has been removed */
#undef HAVE_IOP_GENERIC_READLINK

/* inode_operations has .get_inode_acl member function */
#undef HAVE_IOP_GET_INODE_ACL

/* have iop get_link */
#undef HAVE_IOP_GET_LINK

/* inode_operations has .set_acl member function */
#undef HAVE_IOP_SET_ACL

/* inode_operations has {get,set,remove}xattr members */
#undef HAVE_IOP_XATTR

/* iov_iter_get_pages_alloc2() is available */
#undef HAVE_IOV_ITER_GET_PAGES_ALLOC2

/* if iov_iter has member iter_type */
#undef HAVE_IOV_ITER_HAS_ITER_TYPE_MEMBER

/* if iov_iter has member type */
#undef HAVE_IOV_ITER_HAS_TYPE_MEMBER

/* iov_iter_init handles directional tag */
#undef HAVE_IOV_ITER_INIT_DIRECTION

/* 'iov_iter_iovec' is available */
#undef HAVE_IOV_ITER_IOVEC

/* iov_iter_rw exist */
#undef HAVE_IOV_ITER_RW

/* iov_iter_truncate exists */
#undef HAVE_IOV_ITER_TRUNCATE

/* if iov_iter_type exists */
#undef HAVE_IOV_ITER_TYPE

/* is_root_inode defined */
#undef HAVE_IS_ROOT_INODE

/* 'iter_file_splice_write' exists */
#undef HAVE_ITER_FILE_SPLICE_WRITE

/* iter_iov() is available */
#undef HAVE_ITER_IOV

/* struct address_space has i_pages */
#undef HAVE_I_PAGES

/* if jbd2_journal_get_max_txn_bufs is available */
#undef HAVE_JBD2_JOURNAL_GET_MAX_TXN_BUFS

/* struct jbd2_journal_handle has h_total_credits member */
#undef HAVE_JOURNAL_TOTAL_CREDITS

/* kallsyms_lookup_name is exported by kernel */
#undef HAVE_KALLSYMS_LOOKUP_NAME

/* 'kernel_param_[un]lock' is available */
#undef HAVE_KERNEL_PARAM_LOCK

/* 'struct kernel_param_ops' is available */
#undef HAVE_KERNEL_PARAM_OPS

/* kernel_read() signature ends with loff_t *pos */
#undef HAVE_KERNEL_READ_LAST_POSP

/* kernel_setsockopt still in use */
#undef HAVE_KERNEL_SETSOCKOPT

/* 'getname' has two args */
#undef HAVE_KERN_SOCK_GETNAME_2ARGS

/* keyring_search has 4 args */
#undef HAVE_KEYRING_SEARCH_4ARGS

/* struct key_match_data exist */
#undef HAVE_KEY_MATCH_DATA

/* payload.data is an array */
#undef HAVE_KEY_PAYLOAD_DATA_ARRAY

/* key_type->instantiate has two args */
#undef HAVE_KEY_TYPE_INSTANTIATE_2ARGS

/* key.usage is of type refcount_t */
#undef HAVE_KEY_USAGE_REFCOUNT

/* kfree_sensitive() is available. */
#undef HAVE_KFREE_SENSITIVE

/* kiocb->ki_complete() has 2 arguments */
#undef HAVE_KIOCB_COMPLETE_2ARGS

/* ki_left exist */
#undef HAVE_KIOCB_KI_LEFT

/* ki_nbytes field exist */
#undef HAVE_KI_NBYTES

/* kmap_to_page is exported by the kernel */
#undef HAVE_KMAP_TO_PAGE

/* struct kobj_type has 'default_groups' member */
#undef HAVE_KOBJ_TYPE_DEFAULT_GROUPS

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

/* kref_read() is available */
#undef HAVE_KREF_READ

/* kset_find_obj is exported by the kernel */
#undef HAVE_KSET_FIND_OBJ

/* kernel has kstrtobool_from_user */
#undef HAVE_KSTRTOBOOL_FROM_USER

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

/* ldiskfsfs_dirhash takes an inode argument */
#undef HAVE_LDISKFSFS_GETHASH_INODE_ARG

/* enable use of ldiskfsprogs package */
#undef HAVE_LDISKFSPROGS

/* EXT4_GET_BLOCKS_KEEP_SIZE exists */
#undef HAVE_LDISKFS_GET_BLOCKS_KEEP_SIZE

/* if ldiskfs_iget takes a flags argument */
#undef HAVE_LDISKFS_IGET_WITH_FLAGS

/* 'ext4_journal_ensure_credits' exists */
#undef HAVE_LDISKFS_JOURNAL_ENSURE_CREDITS

/* Enable ldiskfs osd */
#undef HAVE_LDISKFS_OSD

/* libefence support is requested */
#undef HAVE_LIBEFENCE

/* Define to 1 if you have the `keyutils' library (-lkeyutils). */
#undef HAVE_LIBKEYUTILS

/* use libpthread for libcfs library */
#undef HAVE_LIBPTHREAD

/* readline library is available */
#undef HAVE_LIBREADLINE

/* linux/blk-integrity.h is present */
#undef HAVE_LINUX_BLK_INTEGRITY_HEADER

/* linux/filelock.h is present */
#undef HAVE_LINUX_FILELOCK_HEADER

/* linux/fortify-string.h header available */
#undef HAVE_LINUX_FORTIFY_STRING_HEADER

/* linux/stdarg.h is present */
#undef HAVE_LINUX_STDARG_HEADER

/* linux/unaligned.h header is available */
#undef HAVE_LINUX_UNALIGNED_HEADER

/* list_cmp_func_t type is defined */
#undef HAVE_LIST_CMP_FUNC_T

/* lock_manager_operations has lm_compare_owner */
#undef HAVE_LM_COMPARE_OWNER

/* kernel has locks_lock_file_wait in filelock.h */
#undef HAVE_LOCKS_LOCK_FILE_WAIT

/* lock_page_memcg is defined */
#undef HAVE_LOCK_PAGE_MEMCG

/* lookup_user_key() is available */
#undef HAVE_LOOKUP_USER_KEY

/* Enable lru resize support */
#undef HAVE_LRU_RESIZE_SUPPORT

/* lsmcontext has id */
#undef HAVE_LSMCONTEXT_HAS_ID

/* lsmcontext_init is available */
#undef HAVE_LSMCONTEXT_INIT

/* Define this if the Kerberos GSS library supports
   gss_krb5_export_lucid_sec_context */
#undef HAVE_LUCID_CONTEXT_SUPPORT

/* Enable Lustre client crypto via embedded llcrypt */
#undef HAVE_LUSTRE_CRYPTO

/* enum mapping_flags has AS_EXITING flag */
#undef HAVE_MAPPING_AS_EXITING_FLAG

/* match_wildcard() is available */
#undef HAVE_MATCH_WILDCARD

/* memalloc_noreclaim_{save,restore}() is supported */
#undef HAVE_MEMALLOC_RECLAIM

/* Define to 1 if you have the <memory.h> header file. */
#undef HAVE_MEMORY_H

/* mmap_lock API is available. */
#undef HAVE_MMAP_LOCK

/* 'mmap_write_trylock()' is available */
#undef HAVE_MMAP_WRITE_TRYLOCK

/* 'inode_operations' members have mnt_idmap argument */
#undef HAVE_MNT_IDMAP_ARG

/* kernel module loading is possible */
#undef HAVE_MODULE_LOADING_SUPPORT

/* Define to 1 if you have the `name_to_handle_at' function. */
#undef HAVE_NAME_TO_HANDLE_AT

/* support native Linux client */
#undef HAVE_NATIVE_LINUX_CLIENT

/* Define to 1 if you have the <netdb.h> header file. */
#undef HAVE_NETDB_H

/* struct genl_ops has 'start' callback */
#undef HAVE_NETLINK_CALLBACK_START

/* DEFINE_TIMER uses only 2 arguements */
#undef HAVE_NEW_DEFINE_TIMER

/* 'kernel_write' aligns with read/write helpers */
#undef HAVE_NEW_KERNEL_WRITE

/* libnl3 supports nla_get_s32 */
#undef HAVE_NLA_GET_S32

/* libnl3 supports nla_get_s64 */
#undef HAVE_NLA_GET_S64

/* 'nla_strdup' is available */
#undef HAVE_NLA_STRDUP

/* 'nla_strlcpy' is available */
#undef HAVE_NLA_STRLCPY

/* netlink_ext_ack is handled for Netlink dump handlers */
#undef HAVE_NL_DUMP_WITH_EXT_ACK

/* netlink_ext_ack is an argument to nla_parse type function */
#undef HAVE_NL_PARSE_WITH_EXT_ACK

/* no_llseek() is available */
#undef HAVE_NO_LLSEEK

/* NR_UNSTABLE_NFS is still in use. */
#undef HAVE_NR_UNSTABLE_NFS

/* 'struct nsproxy.count' is refcount_t */
#undef HAVE_NSPROXY_COUNT_AS_REFCOUNT

/* ns_to_timespec64() is available */
#undef HAVE_NS_TO_TIMESPEC64

/* with oldsize */
#undef HAVE_OLDSIZE_TRUNCATE_PAGECACHE

/* OpenSSL EVP_PKEY_get_params */
#undef HAVE_OPENSSL_EVP_PKEY

/* openssl-devel is present */
#undef HAVE_OPENSSL_GETSEPOL

/* OpenSSL HMAC functions needed for SSK */
#undef HAVE_OPENSSL_SSK

/* if Oracle OFED Extensions are enabled */
#undef HAVE_ORACLE_OFED_EXTENSIONS

/* 'struct pagevec' is available */
#undef HAVE_PAGEVEC

/* 'pagevec_init' takes one parameter */
#undef HAVE_PAGEVEC_INIT_ONE_PARAM

/* 'page_mapcount_is_type()' is available */
#undef HAVE_PAGE_MAPCOUNT_IS_TYPE

/* linux/panic_notifier.h is present */
#undef HAVE_PANIC_NOTIFIER_H

/* 'param_set_uint_minmax' is available */
#undef HAVE_PARAM_SET_UINT_MINMAX

/* 'percpu_counter_add_batch()' exists */
#undef HAVE_PERCPU_COUNTER_ADD_BATCH

/* percpu_counter_init uses GFP_* flag */
#undef HAVE_PERCPU_COUNTER_INIT_GFP_FLAG

/* 'PageError()()' is available */
#undef HAVE_PG_ERROR

/* 'struct nsproxy' has 'pid_ns_for_children' */
#undef HAVE_PID_NS_FOR_CHILDREN

/* 'posix_acl_update_mode' is available */
#undef HAVE_POSIX_ACL_UPDATE_MODE

/* posix_acl_valid takes struct user_namespace */
#undef HAVE_POSIX_ACL_VALID_USER_NS

/* 'prepare_to_wait_event' is available */
#undef HAVE_PREPARE_TO_WAIT_EVENT

/* processor.h is present */
#undef HAVE_PROCESSOR_H

/* struct proc_ops exists */
#undef HAVE_PROC_OPS

/* get_projid function exists */
#undef HAVE_PROJECT_QUOTA

/* 'PTR_ERR_OR_ZERO' exist */
#undef HAVE_PTR_ERR_OR_ZERO

/* If available, contains the Python version number currently in use. */
#undef HAVE_PYTHON

/* radix_tree_tag_set exists */
#undef HAVE_RADIX_TREE_TAG_SET

/* rdma_connect_locked is defined */
#undef HAVE_RDMA_CONNECT_LOCKED

/* rdma_create_id wants 4 args */
#undef HAVE_RDMA_CREATE_ID_4ARG

/* rdma_create_id wants 5 args */
#undef HAVE_RDMA_CREATE_ID_5ARG

/* rdma_reject has 4 arguments */
#undef HAVE_RDMA_REJECT_4ARGS

/* read_cache_page() filler_t needs struct file */
#undef HAVE_READ_CACHE_PAGE_WANTS_FILE

/* refcount_t is supported */
#undef HAVE_REFCOUNT_T

/* register_shrinker() returns status */
#undef HAVE_REGISTER_SHRINKER_FORMAT_NAMED

/* register_shrinker() returns status */
#undef HAVE_REGISTER_SHRINKER_RET

/* rhashtable_lookup() is available */
#undef HAVE_RHASHTABLE_LOOKUP

/* rhashtable_lookup_get_insert_fast() is available */
#undef HAVE_RHASHTABLE_LOOKUP_GET_INSERT_FAST

/* rhashtable_replace_fast() is available */
#undef HAVE_RHASHTABLE_REPLACE

/* rhashtable_walk_enter() is available */
#undef HAVE_RHASHTABLE_WALK_ENTER

/* struct rhltable exist */
#undef HAVE_RHLTABLE

/* rht_bucket_var() is available */
#undef HAVE_RHT_BUCKET_VAR

/* save_stack_trace_tsk is exported */
#undef HAVE_SAVE_STACK_TRACE_TSK

/* Have sa_spill_alloc in ZFS */
#undef HAVE_SA_SPILL_ALLOC

/* linux/sched header directory exist */
#undef HAVE_SCHED_HEADERS

/* security_dentry_init_security needs lsmcontext */
#undef HAVE_SECURITY_DENTRY_INIT_SECURTY_WITH_CTX

/* security_dentry_init_security() returns xattr name */
#undef HAVE_SECURITY_DENTRY_INIT_WITH_XATTR_NAME_ARG

/* security_release_secctx has 1 arg. */
#undef HAVE_SEC_RELEASE_SECCTX_1ARG

/* support for selinux */
#undef HAVE_SELINUX

/* Define to 1 if you have the <selinux/selinux.h> header file. */
#undef HAVE_SELINUX_SELINUX_H

/* support server */
#undef HAVE_SERVER_SUPPORT

/* Define this if the Kerberos GSS library supports
   gss_krb5_set_allowable_enctypes */
#undef HAVE_SET_ALLOWABLE_ENCTYPES

/* 'shrinker_alloc()' exists */
#undef HAVE_SHRINKER_ALLOC

/* shrinker has count_objects member */
#undef HAVE_SHRINKER_COUNT

/* sk_data_ready uses only one argument */
#undef HAVE_SK_DATA_READY_ONE_ARG

/* sock_create_kern use net as first parameter */
#undef HAVE_SOCK_CREATE_KERN_USE_NET

/* sock_not_owned_by_me defined in sock.h */
#undef HAVE_SOCK_NOT_OWNED_BY_ME

/* Have spa_maxblocksize in ZFS */
#undef HAVE_SPA_MAXBLOCKSIZE

/* struct stacktrace_ops exists */
#undef HAVE_STACKTRACE_OPS

/* Define to 1 if you have the `statx' function. */
#undef HAVE_STATX

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

/* kernel strscpy is available */
#undef HAVE_STRSCPY

/* struct file has f_version */
#undef HAVE_STRUCT_FILE_F_VERSION

/* struct file_lock_core exists */
#undef HAVE_STRUCT_FILE_LOCK_CORE

/* struct posix_acl_xattr_{header,entry} defined */
#undef HAVE_STRUCT_POSIX_ACL_XATTR

/* submit_bio takes two arguments */
#undef HAVE_SUBMIT_BIO_2ARGS

/* 'super_setup_bdi_name' is available */
#undef HAVE_SUPER_SETUP_BDI_NAME

/* symlink inode operations need struct nameidata argument */
#undef HAVE_SYMLINK_OPS_USE_NAMEIDATA

/* new_sync_[read|write] is exported by the kernel */
#undef HAVE_SYNC_READ_WRITE

/* sysfs_emit_at() is defined */
#undef HAVE_SYSFS_EMIT_AT

/* Define to 1 if you have <sys/quota.h>. */
#undef HAVE_SYS_QUOTA_H

/* Define to 1 if you have the <sys/stat.h> header file. */
#undef HAVE_SYS_STAT_H

/* Define to 1 if you have the <sys/types.h> header file. */
#undef HAVE_SYS_TYPES_H

/* 's_uuid' is an uuid_t */
#undef HAVE_S_UUID_AS_UUID_T

/* task_is_running() is defined */
#undef HAVE_TASK_IS_RUNNING

/* 'tcp_sock_set_keepcnt()' exists */
#undef HAVE_TCP_SOCK_SET_KEEPCNT

/* 'tcp_sock_set_keepidle()' exists */
#undef HAVE_TCP_SOCK_SET_KEEPIDLE

/* 'tcp_sock_set_keepintvl()' exists */
#undef HAVE_TCP_SOCK_SET_KEEPINTVL

/* 'tcp_sock_set_nodelay()' exists */
#undef HAVE_TCP_SOCK_SET_NODELAY

/* 'tcp_sock_set_quickack()' exists */
#undef HAVE_TCP_SOCK_SET_QUICKACK

/* timer_delete() is available */
#undef HAVE_TIMER_DELETE

/* timer_delete_sync() is available */
#undef HAVE_TIMER_DELETE_SYNC

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

/* kernel has truncate_inode_pages_final */
#undef HAVE_TRUNCATE_INODE_PAGES_FINAL

/* 'kernel_cap_t' has u64 val */
#undef HAVE_U64_CAPABILITY

/* if MS_RDONLY was moved to uapi/linux/mount.h */
#undef HAVE_UAPI_LINUX_MOUNT_H

/* Define to 1 if you have the <unistd.h> header file. */
#undef HAVE_UNISTD_H

/* use mnt_idmap in place of user_namespace argument */
#undef HAVE_USER_NAMESPACE_ARG

/* 'enum nlmsgerr_attrs' exists */
#undef HAVE_USRSPC_NLMSGERR

/* RDMA_PS_TCP exists */
#undef HAVE_USRSPC_RDMA_PS_TCP

/* 'uuid_t' exist */
#undef HAVE_UUID_T

/* kernel has vfs_rename with 5 args */
#undef HAVE_VFS_RENAME_5ARGS

/* kernel has vfs_rename with 6 args */
#undef HAVE_VFS_RENAME_6ARGS

/* '__vfs_setxattr' is available */
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

/* if struct wait_bit_queue_entry exists */
#undef HAVE_WAIT_BIT_QUEUE_ENTRY

/* 'wait_queue_entry_t' is available */
#undef HAVE_WAIT_QUEUE_ENTRY

/* linux wait_queue_head_t list_head is name head */
#undef HAVE_WAIT_QUEUE_ENTRY_LIST

/* 'wait_var_event' is available */
#undef HAVE_WAIT_VAR_EVENT

/* 'wait_woken, is available' */
#undef HAVE_WAIT_WOKEN

/* write_begin() takes folio */
#undef HAVE_WRITE_BEGIN_FOLIO

/* kernel Xarray implementation lacks 'xa_is_value' */
#undef HAVE_XARRAY_SUPPORT

/* needs inode parameter */
#undef HAVE_XATTR_HANDLER_INODE_PARAM

/* xattr_handler has a name member */
#undef HAVE_XATTR_HANDLER_NAME

/* handler pointer is parameter */
#undef HAVE_XATTR_HANDLER_SIMPLIFIED

/* Have zap_add_by_dnode() in ZFS */
#undef HAVE_ZAP_ADD_BY_DNODE

/* Have zap_lookup_by_dnode() in ZFS */
#undef HAVE_ZAP_LOOKUP_BY_DNODE

/* Have zap_remove_by_dnode() in ZFS */
#undef HAVE_ZAP_REMOVE_ADD_BY_DNODE

/* ZFS arc_prune_func_t uses uint64_t */
#undef HAVE_ZFS_ARC_PRUNE_FUNC_UINT64

/* Have inode_timespec_t */
#undef HAVE_ZFS_INODE_TIMESPEC

/* Have multihost protection in ZFS */
#undef HAVE_ZFS_MULTIHOST

/* ZFS nvlist interfaces require const */
#undef HAVE_ZFS_NVLIST_CONST_INTERFACES

/* Enable zfs osd */
#undef HAVE_ZFS_OSD

/* Have zfs_refcount_add */
#undef HAVE_ZFS_REFCOUNT_ADD

/* Have zfs_refcount.h */
#undef HAVE_ZFS_REFCOUNT_HEADER

/* struct bio has __bi_cnt */
#undef HAVE___BI_CNT

/* 'struct iov_iter' has '__iov' member */
#undef HAVE___IOV_MEMBER

/* if __ldiskfs_find_entry is available */
#undef HAVE___LDISKFS_FIND_ENTRY

/* function pde_data() available */
#undef HAVE_pde_data

/* ext4_journal_start takes 3 arguments */
#undef JOURNAL_START_HAS_3ARGS

/* Define this as the Kerberos version number */
#undef KRB5_VERSION

/* enable libcfs LASSERT, LASSERTF */
#undef LIBCFS_DEBUG

/* use dumplog on panic */
#undef LNET_DUMP_ON_PANIC

/* Define to the sub-directory where libtool stores uninstalled libraries. */
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

/* 'ktime_get_ns' is not available */
#undef NEED_KTIME_GET_NS

/* 'ktime_get_real_ns' is not available */
#undef NEED_KTIME_GET_REAL_NS

/* lockdep_is_held() argument is const */
#undef NEED_LOCKDEP_IS_HELD_DISCARD_CONST

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

/* 'PageError()' replacement */
#undef PageError

/* enable randomly alloc failure */
#undef RANDOM_FAIL_ALLOC

/* no request_mask argument needed */
#undef RQMASK_ARG

/* The size of `unsigned long long', as computed by sizeof. */
#undef SIZEOF_UNSIGNED_LONG_LONG

/* use tunable backoff TCP */
#undef SOCKNAL_BACKOFF

/* tunable backoff TCP in ms */
#undef SOCKNAL_BACKOFF_MS

/* 'struct stacktrace_ops' address function returns an int */
#undef STACKTRACE_OPS_ADDRESS_RETURN_INT

/* Define to 1 if you have the ANSI C header files. */
#undef STDC_HEADERS

/* 'SetPageError()' replacement */
#undef SetPageError

/* name of ldiskfs tune program */
#undef TUNE2FS

/* Define this if the private function, gss_krb5_cache_name, must be used to
   tell the Kerberos library which credentials cache to use. Otherwise, this
   is done by setting the KRB5CCNAME environment variable */
#undef USE_GSS_KRB5_CCACHE_NAME

/* Write when Checking Health */
#undef USE_HEALTH_CHECK_WRITE

/* Version number of package */
#undef VERSION

/* vfs_setxattr() value argument is non-const */
#undef VFS_SETXATTR_VALUE

/* "GDS build enabled" */
#undef WITH_GDS

/* zfs fix version */
#undef ZFS_FIX

/* zfs major version */
#undef ZFS_MAJOR

/* zfs minor version */
#undef ZFS_MINOR

/* zfs patch version */
#undef ZFS_PATCH

/* 'struct iov_iter' has 'iov' member */
#undef __iov

/* 'folio_test_mlocked()' replacement */
#undef folio_test_mlocked_page

/* get_random_u32() is not available, use prandom_u32 */
#undef get_random_u32

/* get_random_u32_below() is not available */
#undef get_random_u32_below

/* 'iov_iter()' provides iov */
#undef iter_iov

/* 'class_create' expects module arg */
#undef ll_class_create

/* need 'page_mapcount_is_type()' replacement */
#undef page_mapcount_is_type

/* function pde_data() unavailable */
#undef pde_data

/* timer_delete() not is available */
#undef timer_delete

/* timer_delete_sync() not is available */
#undef timer_delete_sync
