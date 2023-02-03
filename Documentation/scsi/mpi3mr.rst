This file lists the module parameters supported by the mpi3mr driver and their use.

poll_queues:  Number of queues for io_uring poll mode (allowed values: 0 to 126, default=0).
The mpi3mr driver supports io_uring in the kernel versions >=5.13 and this module parameter allows the user to specify 1 or more queues to be designated as poll_queues. 
The poll_queues are disabled by default and this value is set to 0 by default.

enable_segqueue: Enable segmented operational request & reply queues in the supported controllers (allowed values: 0 and 1, default = 1)
Certain controllers managed by the mpi3mr driver can support the creation of operational request and reply queues with non-contiguous(segmented) memory for the queues.
This option when set to 1, allows the driver to create the queues with segmented memory in the supported controllers.
This option when set to 0, allows the driver to create the queues with contiguous memory.
In the controllers that do not support the segmented queue creation, irrespective of this module parameter value, the driver always uses contiguous memory for queue creation.

drv_dbg_level: Driver diagnostic buffer level (allowed values: 0,1 and 2, default=1).
The mpi3mr driver supports saving some of the driver/kernel log messages from the dmesg log into the controller's persistent memory when certain fault conditions occur in the controller.
This feature helps to save information that could otherwise get lost in cases like the OS drive present behind the controller which gets into fault.
This option when set to 
0(disabled): disables the saving of messages into the controller's persistent memory.
1(minidump): captures the prints related to the specific controller instance that is faulting to the available persistent memory size.
2(fulldump): captures the minidump and in addition captures the complete dmesg logs to the available persistent memory size.

logging_level: Enable additional debug prints in the driver (allowed values: 0 to 0x7fffffff, default=0)
The mpi3mr driver has only mandatorily required information logging by default to avoid cluttering the kernel log. 
The additional debug logging prints can be dynamically enabled by providing the logging level through this module parameter or dynamically changing the logging level value through sysfs on a per controller basis.
The logging level set through module parameter will be applicable to all the controllers managed by the driver.
To turn off the additional logging, the logging level has to be set to 0.
The logging level is a bitmap and the individual values can be be found in the "mpi3mr_debug.h" file. Setting this value to 0xFFFF will turn on pertinent logs required to support debugging many generic issues.

enable_dif: Enable Data Intgerity Format (DIF) for the supported drives (allowed values: 0 and 1, default=1)
The controllers managed by the mpi3mr driver are capable of generating, checking, removing Protection Information(PI) for the drives which support DIF.
The driver by default enables the feature in the controller and let the kernel know that the driver and controller are capable of doing the PI generation and checking.
When this parameter is set to 0, the driver will inform the kernel that the driver and controllers are not capable of supporting DIF.

enable_dix: Enable Data Intgerity Extension (DIX) for the supported drives (allowed values: 0 and 1, default=0)
The controllers managed by the mpi3mr driver and the driver are capable of passing the Protection Information(PI) from the upper layers in the operatings system for the DIF supported drives.
By default, this capability is disabled in the controller and not exposed to the OS by the driver. 
When this parameter is set to 0, the driver will inform the kernel about the DIX capabilities supported by the driver and controller and will handle the I/O requests sent with PI.


