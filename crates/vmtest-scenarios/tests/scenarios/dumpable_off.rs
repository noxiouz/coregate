use vmtest::run_scenario_from_env;
use vmtest_scenarios::dumpable_off_scenario;

#[test]
fn dumpable_off_e2e() {
    if super::skip_if_vm_unset() {
        return;
    }

    let result = run_scenario_from_env(&dumpable_off_scenario())
        .expect("VM dumpable_off e2e failed")
        .expect("scenario should run when COREGATE_VM_IMAGE is set");

    assert!(
        result.core_files.is_empty(),
        "core files should not be present when dumpable is off: {:?}",
        result.core_files
    );
    assert!(
        result.record.is_none(),
        "no crash record should be produced when the kernel suppresses dumping: {:?}",
        result.record
    );
}
