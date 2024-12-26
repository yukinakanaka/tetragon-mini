use aya_ebpf::EbpfContext;
use tetragon_common::process::MsgK8s;
use tetragon_common::vmlinux::*;

#[inline]
pub unsafe fn cgroup_rate<C: EbpfContext>(_ctx: &C, _msg_k8s: &mut MsgK8s, _time: __u64) -> bool {
    // TODO
    true
}
