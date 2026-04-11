use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Error, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    pub binary: Option<String>,
    pub cgroup_prefix: Option<String>,
    pub max_per_minute: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    pub default_max_per_minute: u32,
    pub rules: Vec<RateLimitRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub allowed: bool,
    pub reason: String,
    pub key: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistentState {
    windows: HashMap<String, WindowState>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct WindowState {
    minute_epoch: u64,
    used: u32,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            default_max_per_minute: 30,
            rules: Vec::new(),
        }
    }
}

pub fn check_and_consume_with_file(
    policy: &RateLimitPolicy,
    binary_name: Option<&str>,
    cgroup: Option<&str>,
    state_path: &Path,
    now_epoch_seconds: u64,
) -> std::io::Result<Decision> {
    if let Some(parent) = state_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(state_path)?;

    file.lock_exclusive()?;
    let decision = (|| {
        let mut raw = String::new();
        file.read_to_string(&mut raw)?;

        let mut state: PersistentState = if raw.trim().is_empty() {
            PersistentState::default()
        } else {
            serde_json::from_str(&raw).map_err(|err| Error::new(ErrorKind::InvalidData, err))?
        };

        let (key, max) = select_rule(policy, binary_name, cgroup);
        let minute_epoch = now_epoch_seconds / 60;

        let slot = state.windows.entry(key.clone()).or_default();
        if slot.minute_epoch != minute_epoch {
            slot.minute_epoch = minute_epoch;
            slot.used = 0;
        }

        let decision = if slot.used >= max {
            Decision {
                allowed: false,
                reason: format!("rate_limit_exceeded:{max}/min"),
                key,
            }
        } else {
            slot.used += 1;
            Decision {
                allowed: true,
                reason: "allowed".to_string(),
                key,
            }
        };

        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        serde_json::to_writer(&mut file, &state)?;
        file.flush()?;

        Ok::<Decision, std::io::Error>(decision)
    })();

    let unlock_res = file.unlock();
    match (decision, unlock_res) {
        (Ok(v), Ok(())) => Ok(v),
        (Err(e), _) => Err(e),
        (Ok(_), Err(e)) => Err(e),
    }
}

fn select_rule(
    policy: &RateLimitPolicy,
    binary_name: Option<&str>,
    cgroup: Option<&str>,
) -> (String, u32) {
    let rule = policy
        .rules
        .iter()
        .find(|r| match_rule(r, binary_name, cgroup));

    if let Some(r) = rule {
        let key = format!(
            "bin={};cgroup={}",
            r.binary.as_deref().unwrap_or("*"),
            r.cgroup_prefix.as_deref().unwrap_or("*")
        );
        (key, r.max_per_minute)
    } else {
        ("default".to_string(), policy.default_max_per_minute)
    }
}

fn match_rule(rule: &RateLimitRule, binary_name: Option<&str>, cgroup: Option<&str>) -> bool {
    let bin_ok = match (&rule.binary, binary_name) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(expect), Some(got)) => expect == got,
    };

    let cgroup_ok = match (&rule.cgroup_prefix, cgroup) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(prefix), Some(got)) => got.starts_with(prefix),
    };

    bin_ok && cgroup_ok
}
