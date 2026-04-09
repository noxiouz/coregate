use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use object::read::Object;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashMetadata {
    pub captured_at: DateTime<Utc>,
    pub pid: i32,
    pub tid: Option<i32>,
    pub ns_pid: Option<i32>,
    pub pid_initial_ns: Option<i32>,
    pub tid_initial_ns: Option<i32>,
    pub comm: Option<String>,
    pub signal: Option<i32>,
    pub si_code: Option<i32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub cpu_num: Option<u32>,
    pub thread_name: Option<String>,
    pub hostname: Option<String>,
    pub cmdline: Option<String>,
    pub runtime: Option<String>,
    pub arch: Option<String>,
    pub uname: Option<String>,
    pub kernel_version: Option<String>,
    pub cwd: Option<String>,
    pub root_dir: Option<String>,
    pub coredump_filter: Option<String>,
    pub rlimit_core: Option<String>,
    pub binary_name: Option<String>,
    pub binary_path: Option<String>,
    pub binary_build_id: Option<String>,
    pub uptime_ms: Option<u64>,
    pub cgroup: Option<String>,
    pub binary_removed: Option<bool>,
    pub dumpable: Option<bool>,
    pub package_version: Option<String>,
}

pub fn collect_basic(pid: i32, tid: Option<i32>) -> Result<CrashMetadata> {
    let binary_path = read_exe(pid).ok();
    let binary_removed = binary_path
        .as_ref()
        .map(|p| p.to_string_lossy().ends_with(" (deleted)"));

    let binary_clean_path = binary_path.as_ref().map(|p| clean_deleted_suffix(p));
    let binary_name = binary_clean_path
        .as_ref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string());
    let cmdline = read_cmdline(pid).ok();
    let runtime = infer_runtime(binary_name.as_deref(), cmdline.as_deref());

    Ok(CrashMetadata {
        captured_at: Utc::now(),
        pid,
        tid,
        ns_pid: read_status_value(pid, "NSpid:")
            .and_then(|v| v.split_whitespace().last().and_then(|s| s.parse::<i32>().ok())),
        pid_initial_ns: None,
        tid_initial_ns: None,
        comm: read_process_comm(pid).ok(),
        signal: None,
        si_code: None,
        uid: read_status_id(pid, "Uid:").ok(),
        gid: read_status_id(pid, "Gid:").ok(),
        cpu_num: read_cpu_num(pid, tid).ok(),
        thread_name: read_thread_name(pid, tid).ok(),
        hostname: read_hostname().ok(),
        cmdline,
        runtime,
        arch: read_uname_field("/proc/sys/kernel/osrelease")
            .ok()
            .and_then(|_| read_arch().ok()),
        uname: read_uname().ok(),
        kernel_version: read_kernel_version().ok(),
        cwd: read_proc_link(pid, "cwd").ok(),
        root_dir: read_proc_link(pid, "root").ok(),
        coredump_filter: read_coredump_filter(pid).ok(),
        rlimit_core: read_rlimit_core(pid).ok(),
        binary_name,
        binary_path: binary_clean_path.map(|p| p.to_string_lossy().to_string()),
        binary_build_id: None,
        uptime_ms: read_uptime_ms().ok(),
        cgroup: read_cgroup(pid).ok(),
        binary_removed,
        dumpable: read_status_value(pid, "Dumpable:")
            .and_then(|v| v.trim().parse::<u8>().ok())
            .map(|v| v != 0),
        package_version: None,
    })
}

pub fn enrich_from_binary(metadata: &mut CrashMetadata, enable_package_lookup: bool) {
    let Some(path) = metadata.binary_path.as_deref().map(PathBuf::from) else {
        return;
    };

    metadata.binary_build_id = read_build_id(&path).ok().flatten();

    if enable_package_lookup {
        metadata.package_version = lookup_package_version(&path).ok().flatten();
    }
}

fn read_exe(pid: i32) -> Result<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).context("read /proc/<pid>/exe")
}

fn read_proc_link(pid: i32, name: &str) -> Result<String> {
    let path = fs::read_link(format!("/proc/{pid}/{name}"))
        .with_context(|| format!("read /proc/<pid>/{name}"))?;
    Ok(clean_deleted_suffix(&path).to_string_lossy().to_string())
}

fn read_process_comm(pid: i32) -> Result<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/comm")).context("read process comm")?;
    Ok(raw.trim().to_string())
}

fn read_thread_name(pid: i32, tid: Option<i32>) -> Result<String> {
    let tid = tid.unwrap_or(pid);
    let raw = fs::read_to_string(format!("/proc/{pid}/task/{tid}/comm"))
        .context("read thread name from /proc")?;
    Ok(raw.trim().to_string())
}

fn read_status_value(pid: i32, key: &str) -> Option<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    raw.lines()
        .find(|line| line.starts_with(key))
        .and_then(|line| line.split_once(':').map(|(_, v)| v.trim().to_string()))
}

fn read_status_id(pid: i32, key: &str) -> Result<u32> {
    let value = read_status_value(pid, key).context("missing status id")?;
    let id = value
        .split_whitespace()
        .next()
        .context("missing status id value")?
        .parse::<u32>()
        .context("parse status id")?;
    Ok(id)
}

fn read_coredump_filter(pid: i32) -> Result<String> {
    let raw =
        fs::read_to_string(format!("/proc/{pid}/coredump_filter")).context("read coredump_filter")?;
    Ok(raw.trim().to_string())
}

fn read_rlimit_core(pid: i32) -> Result<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/limits")).context("read limits")?;
    let value = raw
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .and_then(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.len() >= 6).then(|| format!("{} {}", fields[4], fields[5]))
        })
        .context("missing Max core file size line")?;
    Ok(value)
}

fn read_cgroup(pid: i32) -> Result<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup")).context("read cgroup")?;
    let line = raw.lines().next().unwrap_or_default();
    let group = line.rsplit(':').next().unwrap_or_default().trim().to_string();
    Ok(group)
}

fn read_uptime_ms() -> Result<u64> {
    let raw = fs::read_to_string("/proc/uptime").context("read /proc/uptime")?;
    let secs = raw
        .split_whitespace()
        .next()
        .context("missing uptime")?
        .parse::<f64>()
        .context("parse uptime")?;
    Ok((secs * 1000.0) as u64)
}

fn read_hostname() -> Result<String> {
    read_uname_field("/proc/sys/kernel/hostname")
}

fn read_arch() -> Result<String> {
    read_uname_field("/proc/sys/kernel/arch").or_else(|_| {
        let raw = fs::read_to_string("/proc/cpuinfo").context("read /proc/cpuinfo")?;
        let arch = raw
            .lines()
            .find_map(|line| line.split_once(':').map(|(k, v)| (k.trim(), v.trim())))
            .filter(|(k, _)| *k == "Architecture")
            .map(|(_, v)| v.to_string())
            .or_else(|| std::env::consts::ARCH.strip_prefix("").map(ToString::to_string))
            .context("missing architecture")?;
        Ok(arch)
    })
}

fn read_uname() -> Result<String> {
    let sysname = read_uname_field("/proc/sys/kernel/ostype")?;
    let nodename = read_uname_field("/proc/sys/kernel/hostname")?;
    let release = read_uname_field("/proc/sys/kernel/osrelease")?;
    let version = read_uname_field("/proc/sys/kernel/version")?;
    let machine = read_arch()?;
    Ok(format!("{sysname} {nodename} {release} {version} {machine}"))
}

fn read_uname_field(path: &str) -> Result<String> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    Ok(raw.trim().to_string())
}

fn read_cmdline(pid: i32) -> Result<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).context("read /proc/<pid>/cmdline")?;
    let parts = raw
        .split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect::<Vec<_>>();
    Ok(parts.join(" "))
}

fn infer_runtime(binary_name: Option<&str>, cmdline: Option<&str>) -> Option<String> {
    let binary = binary_name?.to_ascii_lowercase();
    let command = cmdline.unwrap_or_default().to_ascii_lowercase();

    let runtime = if is_python_runtime(&binary, &command) {
        "python"
    } else if binary == "node" || binary == "nodejs" || command.starts_with("node ") {
        "nodejs"
    } else if binary == "java" || command.starts_with("java ") {
        "java"
    } else if binary == "ruby" || command.starts_with("ruby ") {
        "ruby"
    } else if binary == "perl" || command.starts_with("perl ") {
        "perl"
    } else if binary == "php" || command.starts_with("php ") {
        "php"
    } else if binary == "bash" || binary == "sh" || binary == "dash" || binary == "zsh" {
        "shell"
    } else {
        "native"
    };

    Some(runtime.to_string())
}

fn is_python_runtime(binary: &str, cmdline: &str) -> bool {
    binary.starts_with("python")
        || binary == "uwsgi"
        || binary == "gunicorn"
        || cmdline.starts_with("python ")
        || cmdline.starts_with("python3 ")
        || cmdline.contains(" python ")
        || cmdline.contains(" python3 ")
}

fn read_cpu_num(pid: i32, tid: Option<i32>) -> Result<u32> {
    let task = tid.unwrap_or(pid);
    let raw = fs::read_to_string(format!("/proc/{pid}/task/{task}/stat"))
        .context("read /proc/<pid>/task/<tid>/stat")?;
    let (_, fields) = split_stat_fields(&raw).context("split stat fields")?;
    let processor = fields
        .get(36)
        .context("missing processor field in stat")?
        .parse::<u32>()
        .context("parse processor field")?;
    Ok(processor)
}

fn split_stat_fields(raw: &str) -> Option<(&str, Vec<&str>)> {
    let end = raw.rfind(") ")?;
    let (head, tail) = raw.split_at(end + 1);
    let fields = tail.get(2..)?.split_whitespace().collect::<Vec<_>>();
    Some((head, fields))
}

fn read_kernel_version() -> Result<String> {
    let raw = fs::read_to_string("/proc/sys/kernel/osrelease")
        .context("read /proc/sys/kernel/osrelease")?;
    Ok(raw.trim().to_string())
}

fn clean_deleted_suffix(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    let cleaned = s.strip_suffix(" (deleted)").unwrap_or(&s);
    PathBuf::from(cleaned)
}

fn read_build_id(path: &Path) -> Result<Option<String>> {
    let buf = fs::read(path).with_context(|| format!("read ELF at {}", path.display()))?;
    let file = object::File::parse(&*buf).context("parse ELF")?;
    let build_id = file.build_id().context("read build-id from ELF")?;
    Ok(build_id.map(hex))
}

fn hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn lookup_package_version(path: &Path) -> Result<Option<String>> {
    if let Some(version) = lookup_dpkg_version(path)? {
        return Ok(Some(version));
    }
    lookup_rpm_version(path)
}

fn lookup_dpkg_version(path: &Path) -> Result<Option<String>> {
    let owner = Command::new("dpkg-query")
        .args(["-S", &path.to_string_lossy()])
        .output();
    let owner = match owner {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .split(':')
            .next()
            .map(str::trim)
            .map(str::to_string),
        _ => None,
    };

    let Some(pkg) = owner else {
        return Ok(None);
    };

    let version = Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", &pkg])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|v| !v.is_empty());

    Ok(version)
}

fn lookup_rpm_version(path: &Path) -> Result<Option<String>> {
    let out = Command::new("rpm")
        .args(["-qf", &path.to_string_lossy(), "--qf", "%{NAME}-%{VERSION}-%{RELEASE}"])
        .output();

    let value = match out {
        Ok(o) if o.status.success() => {
            let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        }
        _ => None,
    };

    Ok(value)
}
