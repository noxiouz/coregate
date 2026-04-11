use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IngressMode {
    PatternPipe,
    Socket,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelDumpRequest {
    pub mode: IngressMode,
    pub pid: i32,
    pub tid: Option<i32>,
    pub signal: Option<i32>,
    pub epoch_seconds: Option<u64>,
    pub exe_hint: Option<String>,
}
