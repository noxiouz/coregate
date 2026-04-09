use vmtest::{deleted_exe_scenario, run_scenario_from_env};

#[test]
fn deleted_exe_e2e() {
    if super::skip_if_vm_unset() {
        return;
    }

    let result = run_scenario_from_env(&deleted_exe_scenario())
        .expect("VM deleted_exe e2e failed")
        .expect("scenario should run when COREGATE_VM_IMAGE is set");

    let record = result.record.as_ref().expect("expected crash record");
    assert_eq!(
        record["metadata"]["binary_removed"].as_bool(),
        Some(true),
        "binary_removed should be true for deleted executable: {}",
        record
    );
    assert!(
        record["metadata"]["binary_path"].as_str().is_some(),
        "binary_path missing in record: {}",
        record
    );
}
