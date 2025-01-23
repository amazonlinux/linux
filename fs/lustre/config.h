/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* enable libcfs CDEBUG, CWARN */
#define CDEBUG_ENABLED 1

/* enable libcfs ENTRY/EXIT */
#define CDEBUG_ENTRY_EXIT 1

/* enable page state tracking code */
/* #undef CONFIG_DEBUG_PAGESTATE_TRACKING */

/* do data checksums */
#define CONFIG_ENABLE_CHECKSUM 1

/* enable flock by default */
#define CONFIG_ENABLE_FLOCK 1

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

/* embedded llcrypt */
#define CONFIG_LL_ENCRYPTION 1

/* enable invariant checking */
/* #undef CONFIG_LUSTRE_DEBUG_EXPENSIVE_CHECK */

/* enable lu_ref reference tracking code */
/* #undef CONFIG_LUSTRE_DEBUG_LU_REF */

/* Use the Pinger */
#define CONFIG_LUSTRE_FS_PINGER 1

/* Enable POSIX acl */
#define CONFIG_LUSTRE_FS_POSIX_ACL 1

/* 'ClearPageError()' replacement */
#define ClearPageError(pg) /**/

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

/* filldir_t return type is bool or int */
#define FILLDIR_TYPE bool

/* rhashtable_walk_init() has 3 args */
/* #undef HAVE_3ARG_RHASHTABLE_WALK_INIT */

/* account_page_dirtied takes three arguments */
/* #undef HAVE_ACCOUNT_PAGE_DIRTIED_3ARGS */

/* account_page_dirtied is exported */
/* #undef HAVE_ACCOUNT_PAGE_DIRTIED_EXPORT */

/* 'get_acl' and 'set_acl' use dentry argument */
#define HAVE_ACL_WITH_DENTRY 1

/* aes-sha2 is supported by krb5 */
/* #undef HAVE_AES_SHA2_SUPPORT */

/* aio_complete defined */
/* #undef HAVE_AIO_COMPLETE */

/* 'alloc_file_pseudo' exist */
#define HAVE_ALLOC_FILE_PSEUDO 1

/* alloc_inode_sb() exists */
#define HAVE_ALLOC_INODE_SB 1

/* struct address_space_operations() has migrate_folio() */
#define HAVE_AOPS_MIGRATE_FOLIO 1

/* struct address_space_operations() has read_folio() */
#define HAVE_AOPS_READ_FOLIO 1

/* struct address_space_operations() has release_folio() */
#define HAVE_AOPS_RELEASE_FOLIO 1

/* Define to 1 if you have the <asm/types.h> header file. */
#define HAVE_ASM_TYPES_H 1

/* backing_dev_info exist */
/* #undef HAVE_BACKING_DEV_INFO */

/* BDI_CAP_MAP_COPY exist */
/* #undef HAVE_BDI_CAP_MAP_COPY */

/* backing_dev_info has io_pages */
#define HAVE_BDI_IO_PAGES 1

/* struct bio has bi_phys_segments member */
/* #undef HAVE_BIO_BI_PHYS_SEGMENTS */

/* bio_endio takes only one argument */
#define HAVE_BIO_ENDIO_USES_ONE_ARG 1

/* 'bio_integrity_enabled' is available */
/* #undef HAVE_BIO_INTEGRITY_ENABLED */

/* kernel has bio_integrity_prep_fn */
/* #undef HAVE_BIO_INTEGRITY_PREP_FN */

/* bio_integrity_prep_fn returns bool */
/* #undef HAVE_BIO_INTEGRITY_PREP_FN_RETURNS_BOOL */

/* 'bio_set_dev' is available */
#define HAVE_BIO_SET_DEV 1

/* bio_integrity_payload.bip_iter exist */
/* #undef HAVE_BIP_ITER_BIO_INTEGRITY_PAYLOAD */

/* Linux bitmap can be allocated */
#define HAVE_BITMAP_ALLOC 1

/* 'bi_bdev' is available */
#define HAVE_BI_BDEV 1

/* struct bio has bi_opf */
#define HAVE_BI_OPF 1

/* 'bi_status' is available */
#define HAVE_BI_STATUS 1

/* kernel has struct blk_integrity_iter */
/* #undef HAVE_BLK_INTEGRITY_ITER */

/* BLK_INTEGRITY_NOVERIFY is available */
#define HAVE_BLK_INTEGRITY_NOVERIFY 1

/* kernel hash_64() is broken */
/* #undef HAVE_BROKEN_HASH_64 */

/* kernel has struct bvec_iter */
#define HAVE_BVEC_ITER 1

/* if bvec_iter_all exists for multi-page bvec iternation */
#define HAVE_BVEC_ITER_ALL 1

/* struct cache_detail has writers */
#define HAVE_CACHE_DETAIL_WRITERS 1

/* if cache_detail->hash_lock is a spinlock */
#define HAVE_CACHE_HASH_SPINLOCK 1

/* cache_head has hlist cache_list */
#define HAVE_CACHE_HEAD_HLIST 1

/* crypto/internal/cipher.h is present */
#define HAVE_CIPHER_H 1

/* kernel has clean_bdev_aliases */
#define HAVE_CLEAN_BDEV_ALIASES 1

/* 'clear_and_wake_up_bit' is available */
#define HAVE_CLEAR_AND_WAKE_UP_BIT 1

/* compat rdma found */
/* #undef HAVE_COMPAT_RDMA */

/* struct ctl_table argument to proc_handler() is const */
#define HAVE_CONST_CTR_TABLE 1

/* copy_file_range() is supported */
#define HAVE_COPY_FILE_RANGE 1

/* 'cpus_read_lock' exist */
#define HAVE_CPUS_READ_LOCK 1

/* crypto_alloc_skcipher is defined */
#define HAVE_CRYPTO_ALLOC_SKCIPHER 1

/* crypto hash helper functions are available */
#define HAVE_CRYPTO_HASH_HELPERS 1

/* 'CRYPTO_MAX_ALG_NAME' is 128 */
#define HAVE_CRYPTO_MAX_ALG_NAME_128 1

/* crypto/sha2.h is present */
#define HAVE_CRYPTO_SHA2_HEADER 1

/* current_time() has replaced CURRENT_TIME */
#define HAVE_CURRENT_TIME 1

/* Have db_dirty_records list_t */
/* #undef HAVE_DB_DIRTY_RECORDS_LIST */

/* default_file_splice_read is exported */
/* #undef HAVE_DEFAULT_FILE_SPLICE_READ_EXPORT */

/* delete_from_page_cache is exported */
/* #undef HAVE_DELETE_FROM_PAGE_CACHE */

/* dentry.d_child exist */
/* #undef HAVE_DENTRY_D_CHILD */

/* sruct dentry has d_children member */
#define HAVE_DENTRY_D_CHILDREN 1

/* list dentry.d_u.d_alias exist */
#define HAVE_DENTRY_D_U_D_ALIAS 1

/* DES3 enctype is supported by krb5 */
/* #undef HAVE_DES3_SUPPORT */

/* direct_IO has 2 arguments */
#define HAVE_DIRECTIO_2ARGS 1

/* direct IO uses iov_iter */
/* #undef HAVE_DIRECTIO_ITER */

/* address_spaace_operaions->dirty_folio() member exists */
#define HAVE_DIRTY_FOLIO 1

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

/* Have dmu_offset_next() exported */
/* #undef HAVE_DMU_OFFSET_NEXT */

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

/* down_write_killable function exists */
#define HAVE_DOWN_WRITE_KILLABLE 1

/* quotactl_ops.set_dqblk takes struct kqid */
#define HAVE_DQUOT_KQID 1

/* quotactl_ops.set_dqblk takes struct qc_dqblk */
#define HAVE_DQUOT_QC_DQBLK 1

/* use mnt_idmap with dquot_transfer */
#define HAVE_DQUOT_TRANSFER_WITH_USER_NS 1

/* Have dsl_pool_config_enter/exit in ZFS */
/* #undef HAVE_DSL_POOL_CONFIG */

/* Have dsl_sync_task_do_nowait in ZFS */
/* #undef HAVE_DSL_SYNC_TASK_DO_NOWAIT */

/* d_compare need 4 arguments */
#define HAVE_D_COMPARE_4ARGS 1

/* d_compare need 5 arguments */
/* #undef HAVE_D_COMPARE_5ARGS */

/* d_count exist */
#define HAVE_D_COUNT 1

/* 'd_init' exists */
#define HAVE_D_INIT 1

/* d_in_lookup is defined */
#define HAVE_D_IN_LOOKUP 1

/* 'd_is_positive' is available */
#define HAVE_D_IS_POSITIVE 1

/* Define to 1 if you have the <endian.h> header file. */
#define HAVE_ENDIAN_H 1

/* enum iter_type has member 'iter_pipe' */
/* #undef HAVE_ENUM_ITER_PIPE */

/* ethtool_link_settings is defined */
#define HAVE_ETHTOOL_LINK_SETTINGS 1

/* Define to 1 if you have the <ext2fs/ext2fs.h> header file. */
/* #undef HAVE_EXT2FS_EXT2FS_H */

/* ext4_bread takes 4 arguments */
/* #undef HAVE_EXT4_BREAD_4ARGS */

/* ext4_(inc|dec)_count() has 2 arguments */
/* #undef HAVE_EXT4_INC_DEC_COUNT_2ARGS */

/* i_dquot is in ext4_inode_info */
/* #undef HAVE_EXT4_INFO_DQUOT */

/* ext4_free_blocks do not require struct buffer_head */
/* #undef HAVE_EXT_FREE_BLOCK_WITH_BUFFER_HEAD */

/* file handle and related syscalls are supported */
#define HAVE_FHANDLE_GLIBC_SUPPORT 1

/* union is unnamed */
/* #undef HAVE_FID2PATH_ANON_UNIONS */

/* filemap_get_folios_contig() is available */
#define HAVE_FILEMAP_GET_FOLIOS_CONTIG 1

/* 'filemap_splice_read' is available */
#define HAVE_FILEMAP_SPLICE_READ 1

/* kernel has file_dentry */
#define HAVE_FILE_DENTRY 1

/* file_operations.[read|write]_iter functions exist */
#define HAVE_FILE_OPERATIONS_READ_WRITE_ITER 1

/* filldir_t needs struct dir_context as argument */
#define HAVE_FILLDIR_USE_CTX 1

/* filldir_t needs struct dir_context and returns bool */
#define HAVE_FILLDIR_USE_CTX_RETURN_BOOL 1

/* '__flush_workqueue(system_wq)' is available */
#define HAVE_FLUSH___WORKQUEUE 1

/* FMR pool API is available */
/* #undef HAVE_FMR_POOL_API */

/* 'struct folio_batch' is available */
#define HAVE_FOLIO_BATCH 1

/* 'folio_batch_reinit' is available */
#define HAVE_FOLIO_BATCH_REINIT 1

/* 'folio_mapcount()' is available */
#define HAVE_FOLIO_MAPCOUNT 1

/* file_operations has iterate_shared */
#define HAVE_FOP_ITERATE_SHARED 1

/* force_sig() has task parameter */
/* #undef HAVE_FORCE_SIG_WITH_TASK */

/* 'struct fscrypt_digested_name' exists */
/* #undef HAVE_FSCRYPT_DIGESTED_NAME */

/* embedded llcrypt uses llcrypt_dummy_context_enabled() */
#define HAVE_FSCRYPT_DUMMY_CONTEXT_ENABLED 1

/* fscrypt_is_nokey_name() exists */
#define HAVE_FSCRYPT_IS_NOKEY_NAME 1

/* full_name_hash need 3 arguments */
#define HAVE_FULL_NAME_HASH_3ARGS 1

/* generic_error_remove_folio() exists */
#define HAVE_GENERIC_ERROR_REMOVE_FOLIO 1

/* 'generic_fillattr()' has request_mask argument */
#define HAVE_GENERIC_FILEATTR_HAS_MASK_ARG 1

/* generic_write_sync has 2 arguments */
#define HAVE_GENERIC_WRITE_SYNC_2ARGS 1

/* struct genl_dumpit_info has family field */
/* #undef HAVE_GENL_DUMPIT_INFO */

/* Define to 1 if you have the `gethostbyname' function. */
#define HAVE_GETHOSTBYNAME 1

/* 'get_acl' has a rcu argument */
/* #undef HAVE_GET_ACL_RCU_ARG */

/* 'get_expiry' takes time64_t */
#define HAVE_GET_EXPIRY_2ARGS 1

/* get_inode_usage function exists */
#define HAVE_GET_INODE_USAGE 1

/* get_random_[u32|u64] are available */
#define HAVE_GET_RANDOM_U32_AND_U64 1

/* get_random_u32_below() is available */
#define HAVE_GET_RANDOM_U32_BELOW 1

/* get_request_key_auth() is available */
#define HAVE_GET_REQUEST_KEY_AUTH 1

/* get_user_pages takes 6 arguments */
/* #undef HAVE_GET_USER_PAGES_6ARG */

/* get_user_pages takes gup_flags in arguments */
/* #undef HAVE_GET_USER_PAGES_GUP_FLAGS */

/* get_user_pages removed 'vma' parameter */
#define HAVE_GET_USER_PAGES_WITHOUT_VMA 1

/* glob_match() is available */
#define HAVE_GLOB 1

/* grab_cache_page_write_begin() has flags argument */
/* #undef HAVE_GRAB_CACHE_PAGE_WRITE_BEGIN_WITH_FLAGS */

/* struct group_info has member gid */
#define HAVE_GROUP_INFO_GID 1

/* 'struct group_info.usage' is refcount_t */
#define HAVE_GROUP_INFO_USAGE_AS_REFCOUNT 1

/* Define this is if you enable gss */
/* #undef HAVE_GSS */

/* Define this if you enable gss keyring backend */
#define HAVE_GSS_KEYRING 1

/* Define this if the Kerberos GSS library supports gss_krb5_ccache_name */
/* #undef HAVE_GSS_KRB5_CCACHE_NAME */

/* '__rhashtable_insert_fast()' returns int */
/* #undef HAVE_HASHTABLE_INSERT_FAST_RETURN_INT */

/* Define this if you have Heimdal Kerberos libraries */
/* #undef HAVE_HEIMDAL */

/* hlist_add_after is available */
/* #undef HAVE_HLIST_ADD_AFTER */

/* hotplug state machine is supported */
#define HAVE_HOTPLUG_STATE_MACHINE 1

/* hypervisor_is_type function exists */
#define HAVE_HYPERVISOR_IS_TYPE 1

/* ibdev_to_node() is defined */
#define HAVE_IBDEV_TO_NODE 1

/* ib_alloc_fast_reg_mr is defined */
/* #undef HAVE_IB_ALLOC_FAST_REG_MR */

/* ib_alloc_pd has 2 arguments */
#define HAVE_IB_ALLOC_PD_2ARGS 1

/* struct ib_cq_init_attr is used by ib_create_cq */
#define HAVE_IB_CQ_INIT_ATTR 1

/* struct ib_device.attrs is defined */
#define HAVE_IB_DEVICE_ATTRS 1

/* if struct ib_device_ops is defined */
/* #undef HAVE_IB_DEVICE_OPS */

/* ib_get_dma_mr is defined */
/* #undef HAVE_IB_GET_DMA_MR */

/* function ib_inc_rkey exist */
#define HAVE_IB_INC_RKEY 1

/* ib_map_mr_sg exists */
#define HAVE_IB_MAP_MR_SG 1

/* ib_map_mr_sg has 5 arguments */
#define HAVE_IB_MAP_MR_SG_5ARGS 1

/* ib_post_send and ib_post_recv have const parameters */
#define HAVE_IB_POST_SEND_RECV_CONST 1

/* struct ib_rdma_wr is defined */
#define HAVE_IB_RDMA_WR 1

/* if ib_sg_dma_address wrapper exists */
/* #undef HAVE_IB_SG_DMA_ADDRESS */

/* inode_operations .getattr member function can gather advance stats */
/* #undef HAVE_INODEOPS_ENHANCED_GETATTR */

/* 'inode_get_ctime()' exists */
#define HAVE_INODE_GET_CTIME 1

/* 'inode_get_mtime()' exists */
#define HAVE_INODE_GET_MTIME_SEC 1

/* inode_lock is defined */
#define HAVE_INODE_LOCK 1

/* inode times are using timespec64 */
/* #undef HAVE_INODE_TIMESPEC64 */

/* blk_integrity.interval exist */
/* #undef HAVE_INTERVAL_BLK_INTEGRITY */

/* blk_integrity.interval_exp exist */
#define HAVE_INTERVAL_EXP_BLK_INTEGRITY 1

/* interval trees use rb_tree_cached */
#define HAVE_INTERVAL_TREE_CACHED 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* address_spaace_operaions->invalidate_folio() member exists */
#define HAVE_INVALIDATE_FOLIO 1

/* address_space invalidate_lock member exists */
#define HAVE_INVALIDATE_LOCK 1

/* address_space_operations.invalidatepage needs 3 arguments */
/* #undef HAVE_INVALIDATE_RANGE */

/* have in_compat_syscall */
#define HAVE_IN_COMPAT_SYSCALL 1

/* 'in_dev_for_each_ifa_rtnl' is defined */
#define HAVE_IN_DEV_FOR_EACH_IFA_RTNL 1

/* inode_operations->rename need flags as argument */
/* #undef HAVE_IOPS_RENAME_WITH_FLAGS */

/* generic_readlink has been removed */
/* #undef HAVE_IOP_GENERIC_READLINK */

/* inode_operations has .get_inode_acl member function */
#define HAVE_IOP_GET_INODE_ACL 1

/* have iop get_link */
#define HAVE_IOP_GET_LINK 1

/* inode_operations has .set_acl member function */
#define HAVE_IOP_SET_ACL 1

/* inode_operations has {get,set,remove}xattr members */
/* #undef HAVE_IOP_XATTR */

/* iov_iter_get_pages_alloc2() is available */
#define HAVE_IOV_ITER_GET_PAGES_ALLOC2 1

/* if iov_iter has member iter_type */
#define HAVE_IOV_ITER_HAS_ITER_TYPE_MEMBER 1

/* if iov_iter has member type */
/* #undef HAVE_IOV_ITER_HAS_TYPE_MEMBER */

/* iov_iter_init handles directional tag */
#define HAVE_IOV_ITER_INIT_DIRECTION 1

/* 'iov_iter_iovec' is available */
/* #undef HAVE_IOV_ITER_IOVEC */

/* iov_iter_rw exist */
#define HAVE_IOV_ITER_RW 1

/* iov_iter_truncate exists */
#define HAVE_IOV_ITER_TRUNCATE 1

/* if iov_iter_type exists */
#define HAVE_IOV_ITER_TYPE 1

/* is_root_inode defined */
#define HAVE_IS_ROOT_INODE 1

/* 'iter_file_splice_write' exists */
#define HAVE_ITER_FILE_SPLICE_WRITE 1

/* iter_iov() is available */
#define HAVE_ITER_IOV 1

/* struct address_space has i_pages */
#define HAVE_I_PAGES 1

/* if jbd2_journal_get_max_txn_bufs is available */
/* #undef HAVE_JBD2_JOURNAL_GET_MAX_TXN_BUFS */

/* struct jbd2_journal_handle has h_total_credits member */
/* #undef HAVE_JOURNAL_TOTAL_CREDITS */

/* kallsyms_lookup_name is exported by kernel */
/* #undef HAVE_KALLSYMS_LOOKUP_NAME */

/* 'kernel_param_[un]lock' is available */
#define HAVE_KERNEL_PARAM_LOCK 1

/* 'struct kernel_param_ops' is available */
#define HAVE_KERNEL_PARAM_OPS 1

/* kernel_read() signature ends with loff_t *pos */
#define HAVE_KERNEL_READ_LAST_POSP 1

/* kernel_setsockopt still in use */
/* #undef HAVE_KERNEL_SETSOCKOPT */

/* 'getname' has two args */
#define HAVE_KERN_SOCK_GETNAME_2ARGS 1

/* keyring_search has 4 args */
#define HAVE_KEYRING_SEARCH_4ARGS 1

/* struct key_match_data exist */
#define HAVE_KEY_MATCH_DATA 1

/* payload.data is an array */
#define HAVE_KEY_PAYLOAD_DATA_ARRAY 1

/* key_type->instantiate has two args */
/* #undef HAVE_KEY_TYPE_INSTANTIATE_2ARGS */

/* key.usage is of type refcount_t */
#define HAVE_KEY_USAGE_REFCOUNT 1

/* kfree_sensitive() is available. */
#define HAVE_KFREE_SENSITIVE 1

/* kiocb->ki_complete() has 2 arguments */
#define HAVE_KIOCB_COMPLETE_2ARGS 1

/* ki_left exist */
/* #undef HAVE_KIOCB_KI_LEFT */

/* ki_nbytes field exist */
/* #undef HAVE_KI_NBYTES */

/* kmap_to_page is exported by the kernel */
/* #undef HAVE_KMAP_TO_PAGE */

/* struct kobj_type has 'default_groups' member */
#define HAVE_KOBJ_TYPE_DEFAULT_GROUPS 1

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

/* kref_read() is available */
#define HAVE_KREF_READ 1

/* kset_find_obj is exported by the kernel */
#define HAVE_KSET_FIND_OBJ 1

/* kernel has kstrtobool_from_user */
#define HAVE_KSTRTOBOOL_FROM_USER 1

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

/* 'ktime_ms_delta' is available */
#define HAVE_KTIME_MS_DELTA 1

/* 'ktime_to_timespec64' is available */
#define HAVE_KTIME_TO_TIMESPEC64 1

/* ldiskfsfs_dirhash takes an inode argument */
/* #undef HAVE_LDISKFSFS_GETHASH_INODE_ARG */

/* enable use of ldiskfsprogs package */
/* #undef HAVE_LDISKFSPROGS */

/* EXT4_GET_BLOCKS_KEEP_SIZE exists */
/* #undef HAVE_LDISKFS_GET_BLOCKS_KEEP_SIZE */

/* if ldiskfs_iget takes a flags argument */
/* #undef HAVE_LDISKFS_IGET_WITH_FLAGS */

/* 'ext4_journal_ensure_credits' exists */
/* #undef HAVE_LDISKFS_JOURNAL_ENSURE_CREDITS */

/* Enable ldiskfs osd */
/* #undef HAVE_LDISKFS_OSD */

/* libefence support is requested */
/* #undef HAVE_LIBEFENCE */

/* Define to 1 if you have the `keyutils' library (-lkeyutils). */
#define HAVE_LIBKEYUTILS 1

/* use libpthread for libcfs library */
#define HAVE_LIBPTHREAD 1

/* readline library is available */
/* #undef HAVE_LIBREADLINE */

/* linux/blk-integrity.h is present */
#define HAVE_LINUX_BLK_INTEGRITY_HEADER 1

/* linux/filelock.h is present */
#define HAVE_LINUX_FILELOCK_HEADER 1

/* linux/fortify-string.h header available */
#define HAVE_LINUX_FORTIFY_STRING_HEADER 1

/* linux/stdarg.h is present */
#define HAVE_LINUX_STDARG_HEADER 1

/* linux/unaligned.h header is available */
#define HAVE_LINUX_UNALIGNED_HEADER 1

/* list_cmp_func_t type is defined */
#define HAVE_LIST_CMP_FUNC_T 1

/* lock_manager_operations has lm_compare_owner */
/* #undef HAVE_LM_COMPARE_OWNER */

/* kernel has locks_lock_file_wait in filelock.h */
#define HAVE_LOCKS_LOCK_FILE_WAIT 1

/* lock_page_memcg is defined */
/* #undef HAVE_LOCK_PAGE_MEMCG */

/* lookup_user_key() is available */
#define HAVE_LOOKUP_USER_KEY 1

/* Enable lru resize support */
#define HAVE_LRU_RESIZE_SUPPORT 1

/* lsmcontext has id */
/* #undef HAVE_LSMCONTEXT_HAS_ID */

/* lsmcontext_init is available */
/* #undef HAVE_LSMCONTEXT_INIT */

/* Define this if the Kerberos GSS library supports
   gss_krb5_export_lucid_sec_context */
/* #undef HAVE_LUCID_CONTEXT_SUPPORT */

/* Enable Lustre client crypto via embedded llcrypt */
#define HAVE_LUSTRE_CRYPTO 1

/* enum mapping_flags has AS_EXITING flag */
#define HAVE_MAPPING_AS_EXITING_FLAG 1

/* match_wildcard() is available */
#define HAVE_MATCH_WILDCARD 1

/* memalloc_noreclaim_{save,restore}() is supported */
#define HAVE_MEMALLOC_RECLAIM 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* mmap_lock API is available. */
#define HAVE_MMAP_LOCK 1

/* 'mmap_write_trylock()' is available */
/* #undef HAVE_MMAP_WRITE_TRYLOCK */

/* 'inode_operations' members have mnt_idmap argument */
#define HAVE_MNT_IDMAP_ARG 1

/* kernel module loading is possible */
#define HAVE_MODULE_LOADING_SUPPORT 1

/* Define to 1 if you have the `name_to_handle_at' function. */
#define HAVE_NAME_TO_HANDLE_AT 1

/* support native Linux client */
/* #undef HAVE_NATIVE_LINUX_CLIENT */

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* struct genl_ops has 'start' callback */
#define HAVE_NETLINK_CALLBACK_START 1

/* DEFINE_TIMER uses only 2 arguements */
#define HAVE_NEW_DEFINE_TIMER 1

/* 'kernel_write' aligns with read/write helpers */
#define HAVE_NEW_KERNEL_WRITE 1

/* libnl3 supports nla_get_s32 */
#define HAVE_NLA_GET_S32 1

/* libnl3 supports nla_get_s64 */
#define HAVE_NLA_GET_S64 1

/* 'nla_strdup' is available */
#define HAVE_NLA_STRDUP 1

/* 'nla_strlcpy' is available */
/* #undef HAVE_NLA_STRLCPY */

/* netlink_ext_ack is handled for Netlink dump handlers */
#define HAVE_NL_DUMP_WITH_EXT_ACK 1

/* netlink_ext_ack is an argument to nla_parse type function */
#define HAVE_NL_PARSE_WITH_EXT_ACK 1

/* no_llseek() is available */
/* #undef HAVE_NO_LLSEEK */

/* NR_UNSTABLE_NFS is still in use. */
/* #undef HAVE_NR_UNSTABLE_NFS */

/* 'struct nsproxy.count' is refcount_t */
#define HAVE_NSPROXY_COUNT_AS_REFCOUNT 1

/* ns_to_timespec64() is available */
#define HAVE_NS_TO_TIMESPEC64 1

/* with oldsize */
/* #undef HAVE_OLDSIZE_TRUNCATE_PAGECACHE */

/* OpenSSL EVP_PKEY_get_params */
/* #undef HAVE_OPENSSL_EVP_PKEY */

/* openssl-devel is present */
#define HAVE_OPENSSL_GETSEPOL 1

/* OpenSSL HMAC functions needed for SSK */
/* #undef HAVE_OPENSSL_SSK */

/* if Oracle OFED Extensions are enabled */
/* #undef HAVE_ORACLE_OFED_EXTENSIONS */

/* 'struct pagevec' is available */
#define HAVE_PAGEVEC 1

/* 'pagevec_init' takes one parameter */
/* #undef HAVE_PAGEVEC_INIT_ONE_PARAM */

/* 'page_mapcount_is_type()' is available */
#define HAVE_PAGE_MAPCOUNT_IS_TYPE 1

/* linux/panic_notifier.h is present */
#define HAVE_PANIC_NOTIFIER_H 1

/* 'param_set_uint_minmax' is available */
#define HAVE_PARAM_SET_UINT_MINMAX 1

/* 'percpu_counter_add_batch()' exists */
#define HAVE_PERCPU_COUNTER_ADD_BATCH 1

/* percpu_counter_init uses GFP_* flag */
#define HAVE_PERCPU_COUNTER_INIT_GFP_FLAG 1

/* 'PageError()()' is available */
/* #undef HAVE_PG_ERROR */

/* 'struct nsproxy' has 'pid_ns_for_children' */
#define HAVE_PID_NS_FOR_CHILDREN 1

/* 'posix_acl_update_mode' is available */
/* #undef HAVE_POSIX_ACL_UPDATE_MODE */

/* posix_acl_valid takes struct user_namespace */
#define HAVE_POSIX_ACL_VALID_USER_NS 1

/* 'prepare_to_wait_event' is available */
#define HAVE_PREPARE_TO_WAIT_EVENT 1

/* processor.h is present */
#define HAVE_PROCESSOR_H 1

/* struct proc_ops exists */
#define HAVE_PROC_OPS 1

/* get_projid function exists */
#define HAVE_PROJECT_QUOTA 1

/* 'PTR_ERR_OR_ZERO' exist */
#define HAVE_PTR_ERR_OR_ZERO 1

/* If available, contains the Python version number currently in use. */
#define HAVE_PYTHON "3.9"

/* radix_tree_tag_set exists */
#define HAVE_RADIX_TREE_TAG_SET 1

/* rdma_connect_locked is defined */
#define HAVE_RDMA_CONNECT_LOCKED 1

/* rdma_create_id wants 4 args */
/* #undef HAVE_RDMA_CREATE_ID_4ARG */

/* rdma_create_id wants 5 args */
#define HAVE_RDMA_CREATE_ID_5ARG 1

/* rdma_reject has 4 arguments */
#define HAVE_RDMA_REJECT_4ARGS 1

/* read_cache_page() filler_t needs struct file */
#define HAVE_READ_CACHE_PAGE_WANTS_FILE 1

/* refcount_t is supported */
#define HAVE_REFCOUNT_T 1

/* register_shrinker() returns status */
/* #undef HAVE_REGISTER_SHRINKER_FORMAT_NAMED */

/* register_shrinker() returns status */
/* #undef HAVE_REGISTER_SHRINKER_RET */

/* rhashtable_lookup() is available */
#define HAVE_RHASHTABLE_LOOKUP 1

/* rhashtable_lookup_get_insert_fast() is available */
#define HAVE_RHASHTABLE_LOOKUP_GET_INSERT_FAST 1

/* rhashtable_replace_fast() is available */
#define HAVE_RHASHTABLE_REPLACE 1

/* rhashtable_walk_enter() is available */
#define HAVE_RHASHTABLE_WALK_ENTER 1

/* struct rhltable exist */
#define HAVE_RHLTABLE 1

/* rht_bucket_var() is available */
#define HAVE_RHT_BUCKET_VAR 1

/* save_stack_trace_tsk is exported */
/* #undef HAVE_SAVE_STACK_TRACE_TSK */

/* Have sa_spill_alloc in ZFS */
/* #undef HAVE_SA_SPILL_ALLOC */

/* linux/sched header directory exist */
#define HAVE_SCHED_HEADERS 1

/* security_dentry_init_security needs lsmcontext */
/* #undef HAVE_SECURITY_DENTRY_INIT_SECURTY_WITH_CTX */

/* security_dentry_init_security() returns xattr name */
#define HAVE_SECURITY_DENTRY_INIT_WITH_XATTR_NAME_ARG 1

/* security_release_secctx has 1 arg. */
/* #undef HAVE_SEC_RELEASE_SECCTX_1ARG */

/* support for selinux */
#define HAVE_SELINUX 1

/* Define to 1 if you have the <selinux/selinux.h> header file. */
#define HAVE_SELINUX_SELINUX_H 1

/* support server */
/* #undef HAVE_SERVER_SUPPORT */

/* Define this if the Kerberos GSS library supports
   gss_krb5_set_allowable_enctypes */
/* #undef HAVE_SET_ALLOWABLE_ENCTYPES */

/* 'shrinker_alloc()' exists */
#define HAVE_SHRINKER_ALLOC 1

/* shrinker has count_objects member */
#define HAVE_SHRINKER_COUNT 1

/* sk_data_ready uses only one argument */
#define HAVE_SK_DATA_READY_ONE_ARG 1

/* sock_create_kern use net as first parameter */
#define HAVE_SOCK_CREATE_KERN_USE_NET 1

/* sock_not_owned_by_me defined in sock.h */
#define HAVE_SOCK_NOT_OWNED_BY_ME 1

/* Have spa_maxblocksize in ZFS */
/* #undef HAVE_SPA_MAXBLOCKSIZE */

/* struct stacktrace_ops exists */
/* #undef HAVE_STACKTRACE_OPS */

/* Define to 1 if you have the `statx' function. */
#define HAVE_STATX 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* stringhash.h is present */
#define HAVE_STRINGHASH 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strnlen' function. */
#define HAVE_STRNLEN 1

/* kernel strscpy is available */
#define HAVE_STRSCPY 1

/* struct file has f_version */
/* #undef HAVE_STRUCT_FILE_F_VERSION */

/* struct file_lock_core exists */
#define HAVE_STRUCT_FILE_LOCK_CORE 1

/* struct posix_acl_xattr_{header,entry} defined */
#define HAVE_STRUCT_POSIX_ACL_XATTR 1

/* submit_bio takes two arguments */
/* #undef HAVE_SUBMIT_BIO_2ARGS */

/* 'super_setup_bdi_name' is available */
#define HAVE_SUPER_SETUP_BDI_NAME 1

/* symlink inode operations need struct nameidata argument */
/* #undef HAVE_SYMLINK_OPS_USE_NAMEIDATA */

/* new_sync_[read|write] is exported by the kernel */
/* #undef HAVE_SYNC_READ_WRITE */

/* sysfs_emit_at() is defined */
#define HAVE_SYSFS_EMIT_AT 1

/* Define to 1 if you have <sys/quota.h>. */
#define HAVE_SYS_QUOTA_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* 's_uuid' is an uuid_t */
#define HAVE_S_UUID_AS_UUID_T 1

/* task_is_running() is defined */
#define HAVE_TASK_IS_RUNNING 1

/* 'tcp_sock_set_keepcnt()' exists */
#define HAVE_TCP_SOCK_SET_KEEPCNT 1

/* 'tcp_sock_set_keepidle()' exists */
#define HAVE_TCP_SOCK_SET_KEEPIDLE 1

/* 'tcp_sock_set_keepintvl()' exists */
#define HAVE_TCP_SOCK_SET_KEEPINTVL 1

/* 'tcp_sock_set_nodelay()' exists */
#define HAVE_TCP_SOCK_SET_NODELAY 1

/* 'tcp_sock_set_quickack()' exists */
#define HAVE_TCP_SOCK_SET_QUICKACK 1

/* timer_delete() is available */
#define HAVE_TIMER_DELETE 1

/* timer_delete_sync() is available */
#define HAVE_TIMER_DELETE_SYNC 1

/* timer_setup has replaced setup_timer */
#define HAVE_TIMER_SETUP 1

/* 'struct timespec64' is available */
#define HAVE_TIMESPEC64 1

/* 'timespec64_sub' is available */
#define HAVE_TIMESPEC64_SUB 1

/* 'timespec64_to_ktime' is available */
#define HAVE_TIMESPEC64_TO_KTIME 1

/* topology_sibling_cpumask is available */
#define HAVE_TOPOLOGY_SIBLING_CPUMASK 1

/* if totalram_pages is a function */
#define HAVE_TOTALRAM_PAGES_AS_FUNC 1

/* kernel has truncate_inode_pages_final */
#define HAVE_TRUNCATE_INODE_PAGES_FINAL 1

/* 'kernel_cap_t' has u64 val */
#define HAVE_U64_CAPABILITY 1

/* if MS_RDONLY was moved to uapi/linux/mount.h */
#define HAVE_UAPI_LINUX_MOUNT_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* use mnt_idmap in place of user_namespace argument */
#define HAVE_USER_NAMESPACE_ARG 1

/* 'enum nlmsgerr_attrs' exists */
#define HAVE_USRSPC_NLMSGERR 1

/* RDMA_PS_TCP exists */
#define HAVE_USRSPC_RDMA_PS_TCP 1

/* 'uuid_t' exist */
#define HAVE_UUID_T 1

/* kernel has vfs_rename with 5 args */
/* #undef HAVE_VFS_RENAME_5ARGS */

/* kernel has vfs_rename with 6 args */
/* #undef HAVE_VFS_RENAME_6ARGS */

/* '__vfs_setxattr' is available */
/* #undef HAVE_VFS_SETXATTR */

/* kernel has vfs_unlink with 3 args */
/* #undef HAVE_VFS_UNLINK_3ARGS */

/* __vmalloc only takes 2 args. */
#define HAVE_VMALLOC_2ARGS 1

/* virtual_address has been replaced by address field */
#define HAVE_VM_FAULT_ADDRESS 1

/* if VM_FAULT_RETRY is defined */
#define HAVE_VM_FAULT_RETRY 1

/* if vm_fault_t type exists */
#define HAVE_VM_FAULT_T 1

/* 'struct vm_operations' remove struct vm_area_struct argument */
#define HAVE_VM_OPS_USE_VM_FAULT_ONLY 1

/* wait_bit.h is present */
#define HAVE_WAIT_BIT_HEADER_H 1

/* if struct wait_bit_queue_entry exists */
#define HAVE_WAIT_BIT_QUEUE_ENTRY 1

/* 'wait_queue_entry_t' is available */
#define HAVE_WAIT_QUEUE_ENTRY 1

/* linux wait_queue_head_t list_head is name head */
#define HAVE_WAIT_QUEUE_ENTRY_LIST 1

/* 'wait_var_event' is available */
#define HAVE_WAIT_VAR_EVENT 1

/* 'wait_woken, is available' */
#define HAVE_WAIT_WOKEN 1

/* write_begin() takes folio */
#define HAVE_WRITE_BEGIN_FOLIO 1

/* kernel Xarray implementation lacks 'xa_is_value' */
#define HAVE_XARRAY_SUPPORT 1

/* needs inode parameter */
/* #undef HAVE_XATTR_HANDLER_INODE_PARAM */

/* xattr_handler has a name member */
#define HAVE_XATTR_HANDLER_NAME 1

/* handler pointer is parameter */
/* #undef HAVE_XATTR_HANDLER_SIMPLIFIED */

/* Have zap_add_by_dnode() in ZFS */
/* #undef HAVE_ZAP_ADD_BY_DNODE */

/* Have zap_lookup_by_dnode() in ZFS */
/* #undef HAVE_ZAP_LOOKUP_BY_DNODE */

/* Have zap_remove_by_dnode() in ZFS */
/* #undef HAVE_ZAP_REMOVE_ADD_BY_DNODE */

/* ZFS arc_prune_func_t uses uint64_t */
/* #undef HAVE_ZFS_ARC_PRUNE_FUNC_UINT64 */

/* Have inode_timespec_t */
/* #undef HAVE_ZFS_INODE_TIMESPEC */

/* Have multihost protection in ZFS */
/* #undef HAVE_ZFS_MULTIHOST */

/* ZFS nvlist interfaces require const */
/* #undef HAVE_ZFS_NVLIST_CONST_INTERFACES */

/* Enable zfs osd */
/* #undef HAVE_ZFS_OSD */

/* Have zfs_refcount_add */
/* #undef HAVE_ZFS_REFCOUNT_ADD */

/* Have zfs_refcount.h */
/* #undef HAVE_ZFS_REFCOUNT_HEADER */

/* struct bio has __bi_cnt */
#define HAVE___BI_CNT 1

/* 'struct iov_iter' has '__iov' member */
#define HAVE___IOV_MEMBER __iov

/* if __ldiskfs_find_entry is available */
/* #undef HAVE___LDISKFS_FIND_ENTRY */

/* function pde_data() available */
#define HAVE_pde_data 1

/* ext4_journal_start takes 3 arguments */
/* #undef JOURNAL_START_HAS_3ARGS */

/* Define this as the Kerberos version number */
/* #undef KRB5_VERSION */

/* enable libcfs LASSERT, LASSERTF */
#define LIBCFS_DEBUG 1

/* use dumplog on panic */
/* #undef LNET_DUMP_ON_PANIC */

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Fourth number in the Lustre version */
#define LUSTRE_FIX 0

/* First number in the Lustre version */
#define LUSTRE_MAJOR 2

/* Second number in the Lustre version */
#define LUSTRE_MINOR 15

/* Third number in the Lustre version */
#define LUSTRE_PATCH 6

/* A copy of PACKAGE_VERSION */
#define LUSTRE_VERSION_STRING "2.15.6_570_ge9974b3"

/* maximum number of MDS threads */
/* #undef MDS_MAX_THREADS */

/* Report minimum OST free space */
/* #undef MIN_DF */

/* name of ldiskfs mkfs program */
#define MKE2FS "mke2fs"

/* 'ktime_get_ns' is not available */
/* #undef NEED_KTIME_GET_NS */

/* 'ktime_get_real_ns' is not available */
/* #undef NEED_KTIME_GET_REAL_NS */

/* lockdep_is_held() argument is const */
/* #undef NEED_LOCKDEP_IS_HELD_DISCARD_CONST */

/* Name of package */
#define PACKAGE "lustre"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://jira.whamcloud.com/"

/* Define to the full name of this package. */
#define PACKAGE_NAME "Lustre"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "Lustre 2.15.6_570_ge9974b3"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "lustre"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.15.6_570_ge9974b3"

/* name of parallel fsck program */
#define PFSCK "fsck"

/* 'PageError()' replacement */
#define PageError(pg) (0)

/* enable randomly alloc failure */
#define RANDOM_FAIL_ALLOC 1

/* no request_mask argument needed */
#define RQMASK_ARG 0,

/* The size of `unsigned long long', as computed by sizeof. */
#define SIZEOF_UNSIGNED_LONG_LONG 8

/* use tunable backoff TCP */
/* #undef SOCKNAL_BACKOFF */

/* tunable backoff TCP in ms */
/* #undef SOCKNAL_BACKOFF_MS */

/* 'struct stacktrace_ops' address function returns an int */
/* #undef STACKTRACE_OPS_ADDRESS_RETURN_INT */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* 'SetPageError()' replacement */
#define SetPageError(pg) /**/

/* name of ldiskfs tune program */
#define TUNE2FS "tune2fs"

/* Define this if the private function, gss_krb5_cache_name, must be used to
   tell the Kerberos library which credentials cache to use. Otherwise, this
   is done by setting the KRB5CCNAME environment variable */
/* #undef USE_GSS_KRB5_CCACHE_NAME */

/* Write when Checking Health */
/* #undef USE_HEALTH_CHECK_WRITE */

/* Version number of package */
#define VERSION "2.15.6_570_ge9974b3"

/* vfs_setxattr() value argument is non-const */
#define VFS_SETXATTR_VALUE(value) ((void *)(value))

/* "GDS build enabled" */
/* #undef WITH_GDS */

/* zfs fix version */
/* #undef ZFS_FIX */

/* zfs major version */
/* #undef ZFS_MAJOR */

/* zfs minor version */
/* #undef ZFS_MINOR */

/* zfs patch version */
/* #undef ZFS_PATCH */

/* 'struct iov_iter' has 'iov' member */
/* #undef __iov */

/* 'folio_test_mlocked()' replacement */
#define folio_test_mlocked_page(pg) folio_test_mlocked(page_folio((pg)))

/* get_random_u32() is not available, use prandom_u32 */
/* #undef get_random_u32 */

/* get_random_u32_below() is not available */
/* #undef get_random_u32_below */

/* 'iov_iter()' provides iov */
/* #undef iter_iov */

/* 'class_create' expects module arg */
#define ll_class_create(name) class_create((name))

/* need 'page_mapcount_is_type()' replacement */
/* #undef page_mapcount_is_type */

/* function pde_data() unavailable */
/* #undef pde_data */

/* timer_delete() not is available */
/* #undef timer_delete */

/* timer_delete_sync() not is available */
/* #undef timer_delete_sync */
