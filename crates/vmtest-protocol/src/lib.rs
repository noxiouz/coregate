use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum VmIngressMode {
    Handle,
    Server,
    ServerLegacy,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VmTestRequest {
    Ping,
    RunScenario {
        scenario_name: String,
        ingress_mode: VmIngressMode,
        guest_setup: Option<String>,
        trigger_command: String,
        expect_record: bool,
    },
    /// Run an arbitrary command inside the VM and return its exit code.
    RunCommand {
        command: String,
        timeout_secs: Option<u64>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VmTestReply {
    Pong,
    ScenarioResult {
        record: Option<Value>,
        core_files: Vec<String>,
        sqlite_present: bool,
        records_jsonl: String,
    },
    /// Result of a RunCommand request.
    CommandResult {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    Error {
        message: String,
    },
}
