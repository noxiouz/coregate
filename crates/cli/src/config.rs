use anyhow::{Context, Result, bail};
use collector_core::Compression;
use collector_limit::{RateLimitPolicy, RateLimitRule};
use collector_meta::CrashMetadata;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fs;
use std::path::{Path, PathBuf};

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/coregate.config.rs"));
}

pub fn deserialize_compression_field<'de, D>(deserializer: D) -> std::result::Result<Option<i32>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum CompressionValue {
        Name(proto::Compression),
        Number(i32),
        Null,
    }

    match Option::<CompressionValue>::deserialize(deserializer)? {
        Some(CompressionValue::Name(value)) => Ok(Some(value as i32)),
        Some(CompressionValue::Number(value)) => Ok(Some(value)),
        Some(CompressionValue::Null) | None => Ok(None),
    }
}

pub fn serialize_compression_field<S>(
    value: &Option<i32>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value.and_then(|raw| proto::Compression::try_from(raw).ok()) {
        Some(value) => value.serialize(serializer),
        None => serializer.serialize_none(),
    }
}

#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    pub output_dir: PathBuf,
    pub metadata_jsonl: PathBuf,
    pub metadata_sqlite: Option<PathBuf>,
    pub limit_state_file: PathBuf,
    pub respect_dumpable: bool,
    pub package_lookup: bool,
    pub core: EffectiveCoreConfig,
    pub rate_limit: RateLimitPolicy,
}

#[derive(Debug, Clone)]
pub struct EffectiveCoreConfig {
    pub compression: Compression,
    pub sparse: bool,
    pub min_free_percent: Option<u8>,
}

impl Default for EffectiveConfig {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from("/var/lib/coregate/cores"),
            metadata_jsonl: PathBuf::from("/var/lib/coregate/records.jsonl"),
            metadata_sqlite: Some(PathBuf::from("/var/lib/coregate/records.sqlite")),
            limit_state_file: PathBuf::from("/var/lib/coregate/ratelimit.json"),
            respect_dumpable: true,
            package_lookup: false,
            core: EffectiveCoreConfig {
                compression: Compression::Zstd,
                sparse: false,
                min_free_percent: None,
            },
            rate_limit: RateLimitPolicy::default(),
        }
    }
}

pub fn load_config_root(path: &Path) -> Result<proto::ConfigRoot> {
    if !path.exists() {
        return Ok(proto::ConfigRoot::default());
    }

    let raw = fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    serde_json::from_str::<proto::ConfigRoot>(&raw).context("parse config JSON into protobuf")
}

pub fn resolve_config(root: &proto::ConfigRoot, metadata: &CrashMetadata) -> Result<EffectiveConfig> {
    let mut resolved = EffectiveConfig::default();

    if let Some(default_cfg) = &root.default {
        apply_collector_config(&mut resolved, default_cfg)?;
    }

    for override_cfg in &root.overrides {
        if matches_metadata(override_cfg.matcher.as_ref(), metadata) {
            if let Some(cfg) = &override_cfg.config {
                apply_collector_config(&mut resolved, cfg)?;
            }
        }
    }

    Ok(resolved)
}

fn matches_metadata(matcher: Option<&proto::Matcher>, metadata: &CrashMetadata) -> bool {
    let Some(matcher) = matcher else {
        return true;
    };

    if let Some(binary_name) = matcher.binary_name.as_deref()
        && metadata.binary_name.as_deref() != Some(binary_name)
    {
        return false;
    }

    if let Some(cgroup_prefix) = matcher.cgroup_prefix.as_deref() {
        let Some(cgroup) = metadata.cgroup.as_deref() else {
            return false;
        };
        if !cgroup.starts_with(cgroup_prefix) {
            return false;
        }
    }

    if let Some(runtime) = matcher.runtime.as_deref()
        && metadata.runtime.as_deref() != Some(runtime)
    {
        return false;
    }

    if let Some(signal) = matcher.signal && metadata.signal != Some(signal) {
        return false;
    }

    true
}

fn apply_collector_config(dst: &mut EffectiveConfig, src: &proto::CollectorConfig) -> Result<()> {
    if let Some(path) = src.output_dir.as_deref() {
        dst.output_dir = PathBuf::from(path);
    }
    if let Some(path) = src.metadata_jsonl.as_deref() {
        dst.metadata_jsonl = PathBuf::from(path);
    }
    if let Some(path) = src.metadata_sqlite.as_deref() {
        dst.metadata_sqlite = if path.is_empty() {
            None
        } else {
            Some(PathBuf::from(path))
        };
    }
    if let Some(path) = src.limit_state_file.as_deref() {
        dst.limit_state_file = PathBuf::from(path);
    }
    if let Some(value) = src.respect_dumpable {
        dst.respect_dumpable = value;
    }
    if let Some(value) = src.package_lookup {
        dst.package_lookup = value;
    }
    if let Some(core) = &src.core {
        apply_core_config(&mut dst.core, core)?;
    }
    if let Some(rate_limit) = &src.rate_limit {
        apply_rate_limit(&mut dst.rate_limit, rate_limit)?;
    }
    Ok(())
}

fn apply_core_config(dst: &mut EffectiveCoreConfig, src: &proto::CoreConfig) -> Result<()> {
    if let Some(value) = src.compression {
        dst.compression = match proto::Compression::try_from(value)
            .context("parse compression enum")?
        {
            proto::Compression::Unspecified => dst.compression,
            proto::Compression::None => Compression::None,
            proto::Compression::Zstd => Compression::Zstd,
            proto::Compression::Xz => Compression::Xz,
        };
    }
    if let Some(value) = src.sparse {
        dst.sparse = value;
    }
    if let Some(value) = src.min_free_percent {
        let value = u8::try_from(value).context("min_free_percent out of range")?;
        if value > 100 {
            bail!("min_free_percent must be <= 100");
        }
        dst.min_free_percent = Some(value);
    }
    Ok(())
}

fn apply_rate_limit(dst: &mut RateLimitPolicy, src: &proto::RateLimitPolicy) -> Result<()> {
    if let Some(value) = src.default_max_per_minute {
        dst.default_max_per_minute = value;
    }
    if !src.rules.is_empty() {
        dst.rules = src
            .rules
            .iter()
            .map(|rule| {
                let max_per_minute = rule
                    .max_per_minute
                    .context("rate limit rule missing max_per_minute")?;
                Ok(RateLimitRule {
                    binary: rule.binary.clone(),
                    cgroup_prefix: rule.cgroup_prefix.clone(),
                    max_per_minute,
                })
            })
            .collect::<Result<Vec<_>>>()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn resolves_default_and_overrides() {
        let root = proto::ConfigRoot {
            default: Some(proto::CollectorConfig {
                package_lookup: Some(false),
                core: Some(proto::CoreConfig {
                    compression: Some(proto::Compression::Zstd as i32),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            overrides: vec![proto::ConfigOverride {
                matcher: Some(proto::Matcher {
                    runtime: Some("python".to_string()),
                    ..Default::default()
                }),
                config: Some(proto::CollectorConfig {
                    package_lookup: Some(true),
                    core: Some(proto::CoreConfig {
                        compression: Some(proto::Compression::Xz as i32),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            }],
        };

        let metadata = CrashMetadata {
            captured_at: Utc::now(),
            pid: 1,
            tid: None,
            ns_pid: None,
            pid_initial_ns: None,
            tid_initial_ns: None,
            comm: None,
            signal: Some(11),
            si_code: None,
            uid: None,
            gid: None,
            cpu_num: None,
            thread_name: None,
            hostname: None,
            cmdline: None,
            runtime: Some("python".to_string()),
            arch: None,
            uname: None,
            kernel_version: None,
            cwd: None,
            root_dir: None,
            coredump_filter: None,
            rlimit_core: None,
            binary_name: Some("python3".to_string()),
            binary_path: None,
            binary_build_id: None,
            uptime_ms: None,
            cgroup: None,
            binary_removed: None,
            dumpable: None,
            package_version: None,
        };

        let resolved = resolve_config(&root, &metadata).expect("resolve config");
        assert!(resolved.package_lookup);
        assert!(matches!(resolved.core.compression, Compression::Xz));
    }
}
