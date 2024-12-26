pub const NANO_PER_SECONDS: usize = 1000000000;
// CLK_TCK is always constant 100 on all architectures except alpha and ia64 which are both
// obsolete and not supported by Tetragon. Also see
// https://lore.kernel.org/lkml/agtlq6$iht$1@penguin.transmeta.com/ and
// https://github.com/containerd/cgroups/pull/12
pub const CLK_TCK: u64 = 100;

// Linux UIDs range from 0..4294967295, the initial mapping of user IDs is 0:0:4294967295.
//
// If Tetragon is not run in this initial mapping due to user namespaces or runtime
// modifications then reading uids of pids from /proc may return the overflow UID 65534
// if the mapping config where Tetragon is running does not have a mapping of the
// uid of the target pid.
// The overflow UID is runtime config at /proc/sys/kernel/{overflowuid,overflowgid}.
//
// The overflow UID historically is also the "nobody" UID, so there is some confusion
// there. Tetragon may get overflowuid from kernel but users could confuse this with
// the "nobody" user that some distributions use.
//
// The UID 4294967295 (-1 as an unsigned integer) is an invalid UID, the kernel
// ignores and return it in some cases where there is no mapping or to indicate
// an invalid UID. So we use it to initialize our UIDs and return it on errors.
pub const INVALID_UID: u32 = !0;
