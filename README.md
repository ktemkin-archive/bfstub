# AArch64 Bareflank Stub

This stub hypervisor remains resident in EL2, and then passes control to a next-
level hypervisor. It is intended both as an example of simple AArch64 'virtualization'
and to allow late-load hypervisors to load themselves, similar to how they can
on x86.
