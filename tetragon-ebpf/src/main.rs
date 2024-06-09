#![no_std]
#![no_main]

mod lib_bpf_cgroup;
mod lib_data_msg;
mod lib_helper;
#[allow(static_mut_refs)]
mod lib_process;
mod maps;
#[allow(static_mut_refs)]
mod process_bpf_execve_event;
#[allow(static_mut_refs)]
mod process_bpf_exit;
#[allow(static_mut_refs)]
mod process_bpf_fork;
mod process_bpf_process_event;
mod process_bpf_rate;
mod process_bpf_task;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
