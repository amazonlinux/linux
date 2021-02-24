.. SPDX-License-Identifier: GPL-2.0

========
SYSGENID
========

The System Generation ID feature is required in virtualized or
containerized environments by applications that work with local copies
or caches of world-unique data such as random values, UUIDs,
monotonically increasing counters, etc.
Such applications can be negatively affected by VM or container
snapshotting when the VM or container is either cloned or returned to
an earlier point in time.

The System Generation ID is meant to help in these scenarios by
providing a monotonically increasing counter that changes each time the
VM or container is restored from a snapshot. The driver for it lives at
``drivers/misc/sysgenid.c``.

The ``sysgenid`` driver exposes a monotonic incremental System
Generation u32 counter via a char-dev filesystem interface accessible
through ``/dev/sysgenid`` that provides sync and async SysGen counter
update notifications. It also provides SysGen counter retrieval and
confirmation mechanisms.

The counter starts from zero when the driver is initialized and
monotonically increments every time the system generation changes.

The ``sysgenid`` driver exports the ``void sysgenid_bump_generation()``
symbol which can be used by backend drivers to drive system generation
changes based on hardware events.
System generation changes can also be driven by userspace software
through a dedicated driver ioctl.

Userspace applications or libraries can (a)synchronously consume the
system generation counter through the provided filesystem interface, to
make any necessary internal adjustments following a system generation
update.

**Please note**, SysGenID alone does not guarantee complete snapshot
safety to applications using it. A certain workflow needs to be
followed at the system level, in order to make the system
snapshot-resilient. Please see the "Snapshot Safety Prerequisites"
section below.

Driver filesystem interface
===========================

``open()``:
  When the device is opened, a copy of the current SysGenID (counter)
  is associated with the open file descriptor. Every open file
  descriptor will have readable data available (EPOLLIN) while its
  current copy of the SysGenID is outdated. Reading from the fd will
  provide the latest SysGenID, while writing to the fd will update the
  fd-local copy of the SysGenID and is used as a confirmation
  mechanism.

``read()``:
  Read is meant to provide the *new* system generation counter when a
  generation change takes place. The read operation blocks until the
  associated counter is no longer up to date, at which point the new
  counter is provided/returned.  Nonblocking ``read()`` returns
  ``EAGAIN`` to signal that there is no *new* counter value available.
  The generation counter is considered *new* for each open file
  descriptor that hasn't confirmed the new value following a generation
  change. Therefore, once a generation change takes place, all
  ``read()`` calls will immediately return the new generation counter
  and will continue to do so until the new value is confirmed back to
  the driver through ``write()``.
  Partial reads are not allowed - read buffer needs to be at least
  32 bits in size.

``write()``:
  Write is used to confirm the up-to-date SysGenID counter back to the
  driver.
  Following a VM generation change, all existing watchers are marked
  as *outdated*. Each file descriptor will maintain the *outdated*
  status until a ``write()`` containing the new up-to-date generation
  counter is used as an update confirmation mechanism.
  Partial writes are not allowed - write buffer should be exactly
  32 bits in size.

``poll()``:
  Poll is implemented to allow polling for generation counter updates.
  Such updates result in ``EPOLLIN`` polling status until the new
  up-to-date counter is confirmed back to the driver through a
  ``write()``.

``ioctl()``:
  The driver also adds support for waiting on open file descriptors
  that haven't acknowledged a generation counter update, as well as a
  mechanism for userspace to *trigger* a generation update:

  - SYSGENID_SET_WATCHER_TRACKING: takes a bool argument to set tracking
    status for current file descriptor. When watcher tracking is
    enabled, the driver tracks this file descriptor as an independent
    *watcher*. The driver keeps accounting of how many watchers have
    confirmed the latest Sys-Gen-Id counter and how many of them are
    *outdated*; an outdated watcher is a *tracked* open file descriptor
    that has lived through a Sys-Gen-Id change but has not yet confirmed
    the new generation counter.
    Software that wants to be waited on by the system while it adjusts
    to generation changes, should turn tracking on. The sysgenid driver
    then keeps track of it and can block system-level adjustment process
    until the software has finished adjusting and confirmed it through a
    ``write()``.
    Tracking is disabled by default and file descriptors need to
    explicitly opt-in using this IOCTL.
  - SYSGENID_WAIT_WATCHERS: blocks until there are no more *outdated*
    tracked watchers or, if a ``timeout`` argument is provided, until
    the timeout expires.
    If the current caller is *outdated* or a generation change happens
    while waiting (thus making current caller *outdated*), the ioctl
    returns ``-EINTR`` to signal the user to handle event and retry.
  - SYSGENID_TRIGGER_GEN_UPDATE: triggers a generation counter increment.
    It takes a ``minimum-generation`` argument which represents the
    minimum value the generation counter will be set to. For example if
    current generation is ``5`` and ``SYSGENID_TRIGGER_GEN_UPDATE(8)``
    is called, the generation counter will increment to ``8``.
    This IOCTL can only be used by processes with CAP_CHECKPOINT_RESTORE
    or CAP_SYS_ADMIN capabilities.

``mmap()``:
  The driver supports ``PROT_READ, MAP_SHARED`` mmaps of a single page
  in size. The first 4 bytes of the mapped page will contain an
  up-to-date u32 copy of the system generation counter.
  The mapped memory can be used as a low-latency generation counter
  probe mechanism in critical sections.
  The mmap() interface is targeted at libraries or code that needs to
  check for generation changes in-line, where an event loop is not
  available or read()/write() syscalls are too expensive.
  In such cases, logic can be added in-line with the sensitive code to
  check and trigger on-demand/just-in-time readjustments when changes
  are detected on the memory mapped generation counter.
  Users of this interface that plan to lazily adjust should not enable
  watcher tracking, since waiting on them doesn't make sense.

``close()``:
  Removes the file descriptor as a system generation counter *watcher*.

Snapshot Safety Prerequisites
=============================

If VM, container or other system-level snapshots happen asynchronously,
at arbitrary times during an active workload there is no practical way
to ensure that in-flight local copies or caches of world-unique data
such as random values, secrets, UUIDs, etc are properly scrubbed and
regenerated.
The challenge stems from the fact that the categorization of data as
snapshot-sensitive is only known to the software working with it, and
this software has no logical control over the moment in time when an
external system snapshot occurs.

Let's take an OpenSSL session token for example. Even if the library
code is made 100% snapshot-safe, meaning the library guarantees that
the session token is unique (any snapshot that happened during the
library call did not duplicate or leak the token), the token is still
vulnerable to snapshot events while it transits the various layers of
the library caller, then the various layers of the OS before leaving
the system.

To catch a secret while it's in-flight, we'd have to validate system
generation at every layer, every step of the way. Even if that would
be deemed the right solution, it would be a long road and a whole
universe to patch before we get there.

Bottom line is we don't have a way to track all of these in-flight
secrets and dynamically scrub them from existence with snapshot
events happening arbitrarily.

Simplifyng assumption - safety prerequisite
-------------------------------------------

**Control the snapshot flow**, disallow snapshots coming at arbitrary
moments in the workload lifetime.

Use a system-level overseer entity that quiesces the system before
snapshot, and post-snapshot-resume oversees that software components
have readjusted to new environment, to the new generation. Only after,
will the overseer un-quiesce the system and allow active workloads.

Software components can choose whether they want to be tracked and
waited on by the overseer by using the ``SYSGENID_SET_WATCHER_TRACKING``
IOCTL.

The sysgenid framework standardizes the API for system software to
find out about needing to readjust and at the same time provides a
mechanism for the overseer entity to wait for everyone to be done, the
system to have readjusted, so it can un-quiesce.

Example snapshot-safe workflow
------------------------------

1) Before taking a snapshot, quiesce the VM/container/system. Exactly
   how this is achieved is very workload-specific, but the general
   description is to get all software to an expected state where their
   event loops dry up and they are effectively quiesced.
2) Take snapshot.
3) Resume the VM/container/system from said snapshot.
4) SysGenID counter will either automatically increment if there is
   a vmgenid backend (hw-driven), or overseer will trigger generation
   bump using ``SYSGENID_TRIGGER_GEN_UPDATE`` IOCLT (sw-driven).
5) Software components which have ``/dev/sysgenid`` in their event
   loops (either using ``poll()`` or ``read()``) are notified of the
   generation change.
   They do their specific internal adjustments. Some may have requested
   to be tracked and waited on by the overseer, others might choose to
   do their adjustments out of band and not block the overseer.
   Tracked ones *must* signal when they are done/ready with a ``write()``
   while the rest *should* also do so for cleanliness, but it's not
   mandatory.
6) Overseer will block and wait for all tracked watchers by using the
   ``SYSGENID_WAIT_WATCHERS`` IOCTL. Once all tracked watchers are done
   in step 5, this overseer will return from this blocking ioctl knowing
   that the system has readjusted and is ready for active workload.
7) Overseer un-quiesces system.
8) There is a class of software, usually libraries, most notably PRNGs
   or SSLs, that don't fit the event-loop model and also have strict
   latency requirements. These can take advantage of the ``mmap()``
   interface and lazily adjust on-demand whenever they are called after
   un-quiesce.
   For a well-designed service stack, these libraries should not be
   called while system is quiesced. When workload is resumed by the
   overseer, on the first call into these libs, they will safely JIT
   readjust.
   Users of this lazy on-demand readjustment model should not enable
   watcher tracking since doing so would introduce a logical deadlock:
   lazy adjustments happen only after un-quiesce, but un-quiesce is
   blocked until all tracked watchers are up-to-date.
