use vmtest::run_scenario_from_env;
use vmtest_scenarios::server_legacy_segv_scenario;

#[test]
fn server_legacy_segv_e2e() {
    if super::skip_if_vm_unset() {
        return;
    }
    if std::env::var_os("COREGATE_VM_KERNEL").is_none()
        || std::env::var_os("COREGATE_VM_INITRD").is_none()
    {
        eprintln!(
            "skipping VM server_legacy_segv test: COREGATE_VM_KERNEL and COREGATE_VM_INITRD are required"
        );
        return;
    }

    let result = run_scenario_from_env(&server_legacy_segv_scenario())
        .expect("VM server_legacy_segv e2e failed")
        .expect("scenario should run when COREGATE_VM_IMAGE is set");

    let record = result.record.as_ref().expect("expected crash record");
    assert!(
        record["core"]["location"]
            .as_str()
            .is_some_and(|location| location.starts_with("file://")),
        "core.location should use file:// URI: {}",
        record
    );
    assert_eq!(
        record["dump"]["reason"].as_str(),
        Some("stored"),
        "server legacy mode should store the core: {}",
        record
    );
}
