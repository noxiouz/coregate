use vmtest::{run_scenario_from_env, storage_refused_scenario};

#[test]
fn storage_refused_e2e() {
    if super::skip_if_vm_unset() {
        return;
    }

    let result = run_scenario_from_env(&storage_refused_scenario())
        .expect("VM storage_refused e2e failed")
        .expect("scenario should run when COREGATE_VM_IMAGE is set");

    let record = result.record.as_ref().expect("expected crash record");
    assert_eq!(
        record["rate_limit"]["key"].as_str(),
        Some("storage"),
        "expected storage decision key in record: {}",
        record
    );
    assert!(
        record["rate_limit"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.starts_with("storage_refused:")),
        "expected storage_refused reason in record: {}",
        record
    );
    assert!(
        result.core_files.is_empty(),
        "core files should be absent when storage is refused: {:?}",
        result.core_files
    );
}
