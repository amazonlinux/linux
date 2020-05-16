L1D Flushing for the paranoid
=============================

With an increasing number of vulnerabilities being reported around data
leaks from L1D, a new user space mechanism to flush the L1D cache on
context switch is added to the kernel. This should help address
CVE-2020-0550 and for paranoid applications, keep them safe from any
yet to be discovered vulnerabilities, related to leaks from the L1D
cache.

Tasks can opt in to this mechanism by using a prctl (implemented only
for x86 at the moment).

Related CVES
------------
At the present moment, the following CVEs can be addressed by this
mechanism

    =============       ========================     ==================
    CVE-2020-0550       Improper Data Forwarding     OS related aspects
    =============       ========================     ==================

Usage Guidelines
----------------
Applications can call ``prctl(2)`` with one of these two arguments

1. PR_SET_L1D_FLUSH - flush the L1D cache on context switch (out)
2. PR_GET_L1D_FLUSH - get the current state of the L1D cache flush, returns 1
   if set and 0 if not set.

**NOTE**: The feature is disabled by default, applications to need to specifically
opt into the feature to enable it.

Mitigation
----------
When PR_SET_L1D_FLUSH is enabled for a task, on switching tasks (when
the address space changes), a flush of the L1D cache is performed for
the task when it leaves the CPU. If the underlying CPU supports L1D
flushing in hardware, the hardware mechanism is used, otherwise a software
fallback, similar to the mechanism used by L1TF is used.
