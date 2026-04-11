//! Crash fixture used by VM scenarios.
//!
//! Each mode intentionally triggers a kernel coredump path with a specific
//! process state, such as non-dumpable or deleted executable.

use std::env;
use std::fs;
use std::process;
use std::thread;

fn main() {
    let mode = env::args().nth(1).unwrap_or_else(|| "segv".to_string());
    match mode.as_str() {
        "segv" => segv(),
        "dumpable-off-segv" => dumpable_off_segv(),
        "self-delete-segv" => self_delete_segv(),
        "thread-segv" => thread_segv(),
        "abort" => process::abort(),
        other => {
            eprintln!("unknown crash mode: {other}");
            process::exit(2);
        }
    }
}

fn segv() -> ! {
    // Force a real SIGSEGV so the kernel coredump path is exercised.
    unsafe {
        let ptr: *mut u8 = std::ptr::null_mut();
        std::ptr::write_volatile(ptr, 1);
    }
    process::abort()
}

fn dumpable_off_segv() -> ! {
    unsafe {
        let rc = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        if rc != 0 {
            eprintln!("prctl(PR_SET_DUMPABLE) failed");
            process::exit(3);
        }
    }
    segv()
}

fn self_delete_segv() -> ! {
    let exe = env::current_exe().unwrap_or_else(|err| {
        eprintln!("current_exe failed: {err}");
        process::exit(4);
    });
    if let Err(err) = fs::remove_file(&exe) {
        eprintln!("remove_file({}) failed: {err}", exe.display());
        process::exit(5);
    }
    segv()
}

fn thread_segv() -> ! {
    let handle = thread::Builder::new()
        .name("crash-worker".to_string())
        .spawn(segv)
        .unwrap_or_else(|err| {
            eprintln!("spawn thread failed: {err}");
            process::exit(6);
        });

    let _ = handle.join();
    process::abort()
}
