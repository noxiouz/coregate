//! Named VM scenarios for Coregate integration tests.
//!
//! Scenario definitions are kept outside the reusable `vmtest` harness so new
//! crash cases can be added without changing the VM orchestration layer.

use serde_json::json;
use vmtest::VmScenario;
use vmtest::protocol::VmIngressMode;

const SCENARIO_CORE_PATTERN_SEGV: &str = "core-pattern-segv";
const SCENARIO_DELETED_EXE: &str = "deleted-exe";
const SCENARIO_DUMPABLE_OFF: &str = "dumpable-off";
const SCENARIO_STORAGE_REFUSED: &str = "storage-refused";
const SCENARIO_THREAD_CRASH: &str = "thread-crash";
const SCENARIO_SERVER_SEGV: &str = "server-segv";
const SCENARIO_SERVER_LEGACY_SEGV: &str = "server-legacy-segv";
const SCENARIO_ALL: &str = "all";

pub fn scenario_names() -> &'static [&'static str] {
    &[
        SCENARIO_CORE_PATTERN_SEGV,
        SCENARIO_DELETED_EXE,
        SCENARIO_DUMPABLE_OFF,
        SCENARIO_STORAGE_REFUSED,
        SCENARIO_THREAD_CRASH,
        SCENARIO_SERVER_SEGV,
        SCENARIO_SERVER_LEGACY_SEGV,
        SCENARIO_ALL,
    ]
}

pub fn scenario_test_filter(name: &str) -> Option<Option<&'static str>> {
    match name {
        SCENARIO_CORE_PATTERN_SEGV => Some(Some("core_pattern_e2e")),
        SCENARIO_DELETED_EXE => Some(Some("deleted_exe_e2e")),
        SCENARIO_DUMPABLE_OFF => Some(Some("dumpable_off_e2e")),
        SCENARIO_STORAGE_REFUSED => Some(Some("storage_refused_e2e")),
        SCENARIO_THREAD_CRASH => Some(Some("thread_crash_e2e")),
        SCENARIO_SERVER_SEGV => Some(Some("server_segv_e2e")),
        SCENARIO_SERVER_LEGACY_SEGV => Some(Some("server_legacy_segv_e2e")),
        SCENARIO_ALL => Some(None),
        _ => None,
    }
}

pub fn core_pattern_segv_scenario() -> VmScenario<'static> {
    VmScenario {
        name: "core_pattern_segv",
        ingress_mode: VmIngressMode::Handle,
        guest_setup: None,
        trigger_command: "ulimit -c unlimited; /usr/local/bin/victim-crash segv",
        config_override: None,
        expect_record: true,
        expect_core: true,
        expect_sqlite: true,
        expect_rate_limit_allowed: Some(true),
        requires_explicit_kernel: false,
    }
}

pub fn dumpable_off_scenario() -> VmScenario<'static> {
    VmScenario {
        name: "dumpable_off",
        ingress_mode: VmIngressMode::Handle,
        guest_setup: None,
        trigger_command: "ulimit -c unlimited; /usr/local/bin/victim-crash dumpable-off-segv",
        config_override: None,
        expect_record: false,
        expect_core: false,
        expect_sqlite: false,
        expect_rate_limit_allowed: None,
        requires_explicit_kernel: false,
    }
}

pub fn deleted_exe_scenario() -> VmScenario<'static> {
    VmScenario {
        name: "deleted_exe",
        ingress_mode: VmIngressMode::Handle,
        guest_setup: None,
        trigger_command: "ulimit -c unlimited; /usr/local/bin/victim-crash self-delete-segv",
        config_override: None,
        expect_record: true,
        expect_core: true,
        expect_sqlite: true,
        expect_rate_limit_allowed: Some(true),
        requires_explicit_kernel: false,
    }
}

pub fn storage_refused_scenario() -> VmScenario<'static> {
    VmScenario {
        name: "storage_refused",
        ingress_mode: VmIngressMode::Handle,
        guest_setup: None,
        trigger_command: "ulimit -c unlimited; /usr/local/bin/victim-crash segv",
        config_override: Some(json!({
            "default": {
                "core": {
                    "min_free_percent": 100
                }
            }
        })),
        expect_record: true,
        expect_core: false,
        expect_sqlite: true,
        expect_rate_limit_allowed: Some(false),
        requires_explicit_kernel: false,
    }
}

pub fn thread_crash_scenario() -> VmScenario<'static> {
    VmScenario {
        name: "thread_crash",
        ingress_mode: VmIngressMode::Handle,
        guest_setup: None,
        trigger_command: "ulimit -c unlimited; /usr/local/bin/victim-crash thread-segv",
        config_override: None,
        expect_record: true,
        expect_core: true,
        expect_sqlite: true,
        expect_rate_limit_allowed: Some(true),
        requires_explicit_kernel: false,
    }
}

pub fn server_segv_scenario() -> VmScenario<'static> {
    VmScenario {
        name: "server_segv",
        ingress_mode: VmIngressMode::Server,
        guest_setup: None,
        trigger_command: "ulimit -c unlimited; /usr/local/bin/victim-crash segv",
        config_override: None,
        expect_record: true,
        expect_core: true,
        expect_sqlite: true,
        expect_rate_limit_allowed: Some(true),
        requires_explicit_kernel: true,
    }
}

pub fn server_legacy_segv_scenario() -> VmScenario<'static> {
    VmScenario {
        name: "server_legacy_segv",
        ingress_mode: VmIngressMode::ServerLegacy,
        guest_setup: None,
        trigger_command: "ulimit -c unlimited; /usr/local/bin/victim-crash segv",
        config_override: None,
        expect_record: true,
        expect_core: true,
        expect_sqlite: true,
        expect_rate_limit_allowed: Some(true),
        requires_explicit_kernel: true,
    }
}
