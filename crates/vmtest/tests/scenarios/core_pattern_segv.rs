use vmtest::{core_pattern_segv_scenario, run_scenario_from_env};

#[test]
fn core_pattern_e2e() {
    if super::skip_if_vm_unset() {
        return;
    }

    let result = run_scenario_from_env(&core_pattern_segv_scenario())
        .expect("VM core_pattern e2e failed")
        .expect("scenario should run when COREGATE_VM_IMAGE is set");

    assert!(
        result
            .record
            .as_ref()
            .and_then(|record| record["metadata"]["binary_name"].as_str())
            .is_some(),
        "binary_name missing in record: {}",
        result
            .record
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<no record>".to_string())
    );

    assert!(
        result
            .record
            .as_ref()
            .and_then(|record| record["metadata"]["runtime"].as_str())
            .is_some(),
        "runtime missing in record: {}",
        result
            .record
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<no record>".to_string())
    );
}
