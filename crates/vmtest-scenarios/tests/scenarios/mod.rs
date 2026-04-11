pub mod core_pattern_segv;
pub mod deleted_exe;
pub mod dumpable_off;
pub mod server_legacy_segv;
pub mod server_segv;
pub mod storage_refused;
pub mod thread_crash;

fn skip_if_vm_unset() -> bool {
    if std::env::var_os("COREGATE_VM_IMAGE").is_none() {
        eprintln!("skipping VM test: COREGATE_VM_IMAGE is not set");
        true
    } else {
        false
    }
}
