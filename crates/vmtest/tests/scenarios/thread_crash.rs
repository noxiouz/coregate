use vmtest::{run_scenario_from_env, thread_crash_scenario};

#[test]
fn thread_crash_e2e() {
    if super::skip_if_vm_unset() {
        return;
    }

    let result = run_scenario_from_env(&thread_crash_scenario())
        .expect("VM thread_crash e2e failed")
        .expect("scenario should run when COREGATE_VM_IMAGE is set");

    let record = result.record.as_ref().expect("expected crash record");
    let metadata = &record["metadata"];

    assert_eq!(
        metadata["thread_name"].as_str(),
        Some("crash-worker"),
        "thread_name should match the named crashing thread: {}",
        record
    );

    let pid = metadata["pid"].as_i64().expect("pid should be present");
    let tid = metadata["tid"].as_i64().expect("tid should be present");
    assert_ne!(
        tid, pid,
        "tid should differ from pid for a non-main crashing thread: {}",
        record
    );
}
