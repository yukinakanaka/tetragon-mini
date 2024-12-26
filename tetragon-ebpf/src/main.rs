#![no_std]
#![no_main]

mod lib_data_msg;
mod lib_helper;
mod lib_process;
mod maps;
mod process_bpf_execve_event;
mod process_bpf_exit;
mod process_bpf_fork;
mod process_bpf_process_event;
mod process_bpf_rate;
mod process_bpf_task;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
