/* src/config.h.  Generated from config.h.in by configure.  */
/* src/config.h.in.  Generated from configure.ac by autoheader.  */

/* have ah core allocation */
#define HAVE_AH_CORE_ALLOCATION 1

/* destroy_ah has return code again */
#define HAVE_AH_CORE_ALLOCATION_DESTROY_RC 1

/* have device ops alloc_pd without ucontext */
#define HAVE_ALLOC_PD_NO_UCONTEXT 1

/* atomic64_fetch_inc exists */
#define HAVE_ATOMIC64_FETCH_INC 1

/* have bitfield.h */
#define HAVE_BITFIELD_H 1

/* have core mmap xarray */
#define HAVE_CORE_MMAP_XA 1

/* have cq core allocation */
#define HAVE_CQ_CORE_ALLOCATION 1

/* rdma_ah_init_attr exists */
#define HAVE_CREATE_AH_INIT_ATTR 1

/* create_ah doesn't have udata */
/* #undef HAVE_CREATE_AH_NO_UDATA */

/* create_ah has rdma_attr */
#define HAVE_CREATE_AH_RDMA_ATTR 1

/* create_ah has udata */
/* #undef HAVE_CREATE_AH_UDATA */

/* create_cq has attr param */
#define HAVE_CREATE_CQ_ATTR 1

/* have device ops create_cq without ucontext */
/* #undef HAVE_CREATE_CQ_NO_UCONTEXT */

/* create/destroy_ah has flags */
/* #undef HAVE_CREATE_DESTROY_AH_FLAGS */

/* have device ops dealloc pd has udata */
/* #undef HAVE_DEALLOC_PD_UDATA */

/* dealloc_pd has udata and return code */
#define HAVE_DEALLOC_PD_UDATA_RC 1

/* have device ops dereg mr udata */
#define HAVE_DEREG_MR_UDATA 1

/* have device ops destroy cq udata */
#define HAVE_DESTROY_CQ_UDATA 1

/* have device ops destroy qp udata */
#define HAVE_DESTROY_QP_UDATA 1

/* dev has parent field */
#define HAVE_DEV_PARENT 1

/* driver_id field exists */
/* #undef HAVE_DRIVER_ID */

/* efa gdr enabled */
/* #undef HAVE_EFA_GDR */

/* get_port_immutable exists */
#define HAVE_GET_PORT_IMMUTABLE 1

/* have hw_stats */
#define HAVE_HW_STATS 1

/* have ibdev print */
#define HAVE_IBDEV_PRINT 1

/* have ibdev ratelimited print */
#define HAVE_IBDEV_PRINT_RATELIMITED 1

/* IB_ACCESS_OPTIONAL exists */
#define HAVE_IB_ACCESS_OPTIONAL 1

/* ib_device_ops has common fields */
#define HAVE_IB_DEVICE_OPS_COMMON 1

/* struct ib_device_ops exists */
#define HAVE_IB_DEV_OPS 1

/* destroy_cq has return code again */
#define HAVE_IB_INT_DESTROY_CQ 1

/* have ib_is_udata_cleared */
#define HAVE_IB_IS_UDATA_CLEARED 1

/* ib_modify_qp_is_ok has four params */
#define HAVE_IB_MODIFY_QP_IS_OK_FOUR_PARAMS 1

/* ib_mr has length field */
#define HAVE_IB_MR_LENGTH 1

/* ib_mtu_int_to_enum exists */
#define HAVE_IB_MTU_INT_TO_ENUM 1

/* have ib port phys state link up */
#define HAVE_IB_PORT_PHYS_STATE_LINK_UP 1

/* have driver qpt */
#define HAVE_IB_QPT_DRIVER 1

/* query_device has udata */
#define HAVE_IB_QUERY_DEVICE_UDATA 1

/* ib_register_device has dma_device param */
#define HAVE_IB_REGISTER_DEVICE_DMA_DEVICE_PARAM 1

/* ib_register_device has name param */
/* #undef HAVE_IB_REGISTER_DEVICE_NAME_PARAM */

/* ib_register_device has two params */
/* #undef HAVE_IB_REGISTER_DEVICE_TWO_PARAMS */

/* ib_umem_find_single_pg_size exists */
#define HAVE_IB_UMEM_FIND_SINGLE_PG_SIZE 1

/* have ib_umem_get device param */
#define HAVE_IB_UMEM_GET_DEVICE_PARAM 1

/* ib_umem_get has no dmasync parameter */
#define HAVE_IB_UMEM_GET_NO_DMASYNC 1

/* ib_umem_get has udata */
/* #undef HAVE_IB_UMEM_GET_UDATA */

/* ib_umem_num_dma_blocks exists */
#define HAVE_IB_UMEM_NUM_DMA_BLOCKS 1

/* have void destroy cq */
/* #undef HAVE_IB_VOID_DESTROY_CQ */

/* have kvzalloc */
#define HAVE_KVZALLOC 1

/* ib_device_attr has max_send_recv_sge */
#define HAVE_MAX_SEND_RCV_SGE 1

/* have no kverbs drivers */
#define HAVE_NO_KVERBS_DRIVERS 1

/* have pci_irq_vector */
#define HAVE_PCI_IRQ_VECTOR 1

/* have amazon pci id */
#define HAVE_PCI_VENDOR_ID_AMAZON 1

/* have pd core allocation */
#define HAVE_PD_CORE_ALLOCATION 1

/* have const wr in post verbs */
#define HAVE_POST_CONST_WR 1

/* have unspecified node type */
#define HAVE_RDMA_NODE_UNSPECIFIED 1

/* rdma_umem_for_each_dma_block exists */
#define HAVE_RDMA_UMEM_FOR_EACH_DMA_BLOCK 1

/* rdma_user_mmap_io exists */
/* #undef HAVE_RDMA_USER_MMAP_IO */

/* safe ib_alloc_device exists */
#define HAVE_SAFE_IB_ALLOC_DEVICE 1

/* for_each_sg_dma_page exists */
#define HAVE_SG_DMA_PAGE_ITER 1

/* have ucontext core allocation */
#define HAVE_UCONTEXT_CORE_ALLOCATION 1

/* rdma_udata_to_drv_context exists */
#define HAVE_UDATA_TO_DRV_CONTEXT 1

/* ib umem scatterlist exists */
#define HAVE_UMEM_SCATTERLIST_IF 1

/* have upstream efa */
#define HAVE_UPSTREAM_EFA 1

/* have uverbs command header fix */
/* #undef HAVE_UVERBS_CMD_HDR_FIX */

/* uverbs_cmd_mask is not needed */
/* #undef HAVE_UVERBS_CMD_MASK_NOT_NEEDED */

/* Name of package */
#define PACKAGE "efa"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "efa"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "efa 1.11.1"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "efa"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.11.1"

/* Version number of package */
#define VERSION "1.11.1"
