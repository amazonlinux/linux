.. SPDX-License-Identifier: GPL-2.0

=======
VMGENID
=======

The VM Generation ID is a feature defined by Microsoft (paper:
http://go.microsoft.com/fwlink/?LinkId=260709) and supported by
multiple hypervisor vendors.

The feature is required in virtualized environments by applications
that work with local copies/caches of world-unique data such as random
values, UUIDs, monotonically increasing counters, etc.
Such applications can be negatively affected by VM snapshotting when
the VM is either cloned or returned to an earlier point in time.

The VM Generation ID is a simple concept through which a hypevisor
notifies its guest that a snapshot has taken place. The vmgenid device
provides a unique ID that changes each time the VM is restored from a
snapshot. The hardware provided UUID value can be used to differentiate
between VMs or different generations of the same VM.

The VM Generation ID is exposed through an ACPI device by multiple
hypervisor vendors. The driver for it lives at
``drivers/virt/vmgenid.c``

The ``vmgenid`` driver acts as a backend for the ``sysgenid`` kernel module
(``drivers/misc/sysgenid.c``, ``Documentation/misc-devices/sysgenid.rst``)
to drive changes to the "System Generation Id" which is further exposed
to userspace as a monotonically increasing counter.

The driver uses ACPI events to be notified by hardware of changes to the
128-bit Vm Gen Id UUID. Since the actual UUID value is not directly exposed
to userspace, but only used to drive the System Generation Counter, the
driver also adds it as device randomness to improve kernel entropy
following VM snapshot events.
