//! Host-side QEMU VM test harness.
//!
//! This crate owns the reusable VM machinery: image fetching, cloud-init
//! generation, tool injection, QEMU startup, and the host side of the control
//! channel. Named Coregate scenarios live in `vmtest-scenarios`.

mod control;
pub mod protocol;

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use tempfile::TempDir;

use crate::control::{ControlChannel, ensure_parent};
use crate::protocol::{VmIngressMode, VmTestReply, VmTestRequest};

pub const DEFAULT_DEBIAN_SUITE: &str = "bookworm";
pub const DEFAULT_DEBIAN_ARCH: &str = "amd64";
pub const DEFAULT_GUEST_TARGET: &str = "x86_64-unknown-linux-musl";

#[derive(Debug, Clone)]
pub struct CorePatternE2eOptions {
    pub image: PathBuf,
    pub kernel: Option<PathBuf>,
    pub initrd: Option<PathBuf>,
    pub append: Option<String>,
    pub collector: Option<PathBuf>,
    pub victim: Option<PathBuf>,
    pub agent: Option<PathBuf>,
    pub workdir: Option<PathBuf>,
    pub memory_mib: u32,
    pub cpus: u8,
}

#[derive(Debug, Clone)]
pub struct VmScenario<'a> {
    pub name: &'a str,
    pub ingress_mode: VmIngressMode,
    pub guest_setup: Option<&'a str>,
    pub trigger_command: &'a str,
    pub config_override: Option<Value>,
    pub expect_record: bool,
    pub expect_core: bool,
    pub expect_sqlite: bool,
    pub expect_rate_limit_allowed: Option<bool>,
    pub requires_explicit_kernel: bool,
}

#[derive(Debug)]
pub struct CorePatternE2eResult {
    pub artifacts_dir: PathBuf,
    pub record: Option<Value>,
    pub core_files: Vec<String>,
    pub sqlite_present: bool,
    pub serial_log: PathBuf,
}

impl serde::Serialize for CorePatternE2eResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        json!({
            "artifacts_dir": self.artifacts_dir,
            "record": self.record,
            "core_files": self.core_files,
            "sqlite_present": self.sqlite_present,
            "serial_log": self.serial_log,
        })
        .serialize(serializer)
    }
}

pub fn fetch_debian_image(output: Option<PathBuf>, suite: &str, arch: &str) -> Result<PathBuf> {
    ensure!(
        suite == DEFAULT_DEBIAN_SUITE,
        "unsupported Debian suite '{suite}', only '{DEFAULT_DEBIAN_SUITE}' is implemented"
    );
    ensure!(
        arch == DEFAULT_DEBIAN_ARCH,
        "unsupported Debian arch '{arch}', only '{DEFAULT_DEBIAN_ARCH}' is implemented"
    );

    let destination = output.unwrap_or_else(|| default_debian_image_path_for(suite, arch));
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let image_url = debian_image_url(suite, arch);
    let sums_url = format!("{}/SHA512SUMS", debian_latest_dir(suite));
    let checksum_path = destination.with_extension("qcow2.SHA512SUMS");

    run(Command::new("curl")
        .arg("-fL")
        .arg("-o")
        .arg(&destination)
        .arg(&image_url))
    .with_context(|| format!("download Debian image from {image_url}"))?;

    let sums_output = run(Command::new("curl").arg("-fL").arg(&sums_url))
        .with_context(|| format!("download checksums from {sums_url}"))?;
    fs::write(&checksum_path, &sums_output.stdout).context("write SHA512SUMS file")?;
    verify_debian_checksum(&destination, &checksum_path, suite, arch)?;

    Ok(destination)
}

pub fn default_debian_image_path() -> PathBuf {
    default_debian_image_path_for(DEFAULT_DEBIAN_SUITE, DEFAULT_DEBIAN_ARCH)
}

pub fn options_from_env() -> Result<Option<CorePatternE2eOptions>> {
    let Some(image) = env_path("COREGATE_VM_IMAGE") else {
        return Ok(None);
    };

    Ok(Some(CorePatternE2eOptions {
        image,
        kernel: env_path("COREGATE_VM_KERNEL"),
        initrd: env_path("COREGATE_VM_INITRD"),
        append: env::var("COREGATE_VM_APPEND").ok(),
        collector: env_path("COREGATE_COLLECTOR_BIN"),
        victim: env_path("COREGATE_VICTIM_BIN"),
        agent: env_path("COREGATE_VMTEST_AGENT_BIN"),
        workdir: env_path("COREGATE_VM_WORKDIR"),
        memory_mib: env::var("COREGATE_VM_MEMORY_MIB")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(2048),
        cpus: env::var("COREGATE_VM_CPUS")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(2),
    }))
}

pub fn run_scenario_from_env(scenario: &VmScenario<'_>) -> Result<Option<CorePatternE2eResult>> {
    let Some(opts) = options_from_env()? else {
        return Ok(None);
    };
    run_scenario(opts, scenario).map(Some)
}

/// Options for running an arbitrary test binary inside a VM.
#[derive(Debug, Clone)]
pub struct RunTestOptions {
    pub image: PathBuf,
    pub kernel: Option<PathBuf>,
    pub initrd: Option<PathBuf>,
    pub append: Option<String>,
    pub agent: PathBuf,
    pub test_binary: PathBuf,
    pub memory_mib: u32,
    pub cpus: u8,
    pub timeout_secs: u64,
    pub guest_setup: Option<String>,
    pub extra_files: Vec<PathBuf>,
    pub workdir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct GuestCommandOptions {
    pub image: PathBuf,
    pub kernel: Option<PathBuf>,
    pub initrd: Option<PathBuf>,
    pub append: Option<String>,
    pub agent: PathBuf,
    pub memory_mib: u32,
    pub cpus: u8,
    pub timeout_secs: u64,
    pub guest_setup: Option<String>,
    pub extra_files: Vec<PathBuf>,
    pub workdir: Option<PathBuf>,
    pub command: String,
}

#[derive(Debug, Clone)]
pub struct GuestCommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Boot a VM, copy the test binary in, execute it, return its exit code.
pub fn run_test(opts: RunTestOptions) -> Result<i32> {
    let command = format!(
        "/usr/local/bin/{}",
        opts.test_binary
            .file_name()
            .context("test binary has no filename")?
            .to_string_lossy()
    );
    let result = run_guest_command(GuestCommandOptions {
        image: opts.image,
        kernel: opts.kernel,
        initrd: opts.initrd,
        append: opts.append,
        agent: opts.agent,
        memory_mib: opts.memory_mib,
        cpus: opts.cpus,
        timeout_secs: opts.timeout_secs,
        guest_setup: opts.guest_setup,
        extra_files: {
            let mut files = opts.extra_files;
            files.push(opts.test_binary);
            files
        },
        workdir: opts.workdir,
        command,
    })?;
    if !result.stdout.is_empty() {
        eprint!("{}", result.stdout);
    }
    if !result.stderr.is_empty() {
        eprint!("{}", result.stderr);
    }
    Ok(result.exit_code)
}

pub fn run_guest_command(opts: GuestCommandOptions) -> Result<GuestCommandResult> {
    ensure!(
        opts.image.exists(),
        "image not found: {}",
        opts.image.display()
    );
    ensure!(
        opts.agent.exists(),
        "agent binary not found: {}",
        opts.agent.display()
    );
    ensure!(
        opts.kernel.is_some() == opts.initrd.is_some(),
        "kernel and initrd must either both be set or both be unset"
    );
    if let Some(kernel) = &opts.kernel {
        ensure!(kernel.exists(), "kernel not found: {}", kernel.display());
    }
    if let Some(initrd) = &opts.initrd {
        ensure!(initrd.exists(), "initrd not found: {}", initrd.display());
    }
    for path in &opts.extra_files {
        ensure!(path.exists(), "extra file not found: {}", path.display());
    }

    let keep_workdir = env::var_os("COREGATE_VM_KEEP_WORKDIR").is_some();
    let tempdir = tempdir_in(opts.workdir.as_deref())?;
    let tempdir_path = tempdir.path().to_path_buf();
    let paths = HarnessPaths::new(tempdir.path());

    // Write a minimal cloud-init that only sets up the agent and mounts tools.
    write_run_test_cloud_init(&paths)?;
    create_seed_image(&paths)?;
    create_run_test_tools_image(&paths, &opts.agent, &opts.extra_files)?;
    create_overlay_image(&opts.image, &paths.overlay_image)?;

    let e2e_opts = CorePatternE2eOptions {
        image: opts.image.clone(),
        kernel: opts.kernel,
        initrd: opts.initrd,
        append: opts.append,
        collector: None,
        victim: None,
        agent: Some(opts.agent.clone()),
        workdir: opts.workdir.clone(),
        memory_mib: opts.memory_mib,
        cpus: opts.cpus,
    };

    let mut qemu = spawn_qemu(&e2e_opts, &paths)?;
    let serial_log = SerialLogFollower::spawn(paths.serial_log.clone(), "run-test");
    let result = (|| -> Result<GuestCommandResult> {
        let mut control = ControlChannel::connect(&mut qemu, &paths.control_socket, || {
            format_qemu_stderr_tail(&paths.qemu_stderr)
        })?;

        // Optionally run guest setup commands first.
        if let Some(setup) = &opts.guest_setup
            && !setup.is_empty()
        {
            let reply = control.request(&VmTestRequest::RunCommand {
                command: setup.clone(),
                timeout_secs: Some(60),
            })?;
            match reply {
                VmTestReply::CommandResult {
                    exit_code, stderr, ..
                } => {
                    if exit_code != 0 {
                        bail!("guest setup command failed (exit {exit_code}): {stderr}");
                    }
                }
                VmTestReply::Error { message } => bail!("guest setup error: {message}"),
                _ => bail!("unexpected reply to setup command"),
            }
        }

        let reply = control.request(&VmTestRequest::RunCommand {
            command: opts.command.clone(),
            timeout_secs: Some(opts.timeout_secs),
        })?;

        match reply {
            VmTestReply::CommandResult {
                exit_code,
                stdout,
                stderr,
            } => Ok(GuestCommandResult {
                exit_code,
                stdout,
                stderr,
            }),
            VmTestReply::Error { message } => bail!("guest agent error: {message}"),
            _ => bail!("unexpected reply to run-test command"),
        }
    })();

    shutdown_qemu(&mut qemu);
    drop(serial_log);
    if result.is_err() && keep_workdir {
        eprintln!(
            "[vmtest run-test] preserved workdir at {}",
            tempdir_path.display()
        );
        let _ = tempdir.keep();
    }
    result
}

pub fn run_scenario(
    opts: CorePatternE2eOptions,
    scenario: &VmScenario<'_>,
) -> Result<CorePatternE2eResult> {
    ensure!(
        opts.image.exists(),
        "image not found: {}",
        opts.image.display()
    );
    ensure!(
        !scenario.requires_explicit_kernel || opts.kernel.is_some(),
        "scenario '{}' requires an explicit 6.16+ guest kernel; set COREGATE_VM_KERNEL and COREGATE_VM_INITRD",
        scenario.name
    );
    ensure!(
        opts.kernel.is_some() == opts.initrd.is_some(),
        "kernel and initrd must either both be set or both be unset"
    );
    if let Some(kernel) = &opts.kernel {
        ensure!(kernel.exists(), "kernel not found: {}", kernel.display());
    }
    if let Some(initrd) = &opts.initrd {
        ensure!(initrd.exists(), "initrd not found: {}", initrd.display());
    }

    let collector = opts
        .collector
        .clone()
        .unwrap_or_else(default_collector_path);
    let victim = opts.victim.clone().unwrap_or_else(default_victim_path);
    let agent = opts.agent.clone().unwrap_or_else(default_agent_path);
    ensure!(
        collector.exists(),
        "collector binary not found: {}",
        collector.display()
    );
    ensure!(
        victim.exists(),
        "victim binary not found: {}",
        victim.display()
    );
    ensure!(
        agent.exists(),
        "vmtest-agent binary not found: {}",
        agent.display()
    );

    let keep_workdir = env::var_os("COREGATE_VM_KEEP_WORKDIR").is_some();
    let tempdir = tempdir_in(opts.workdir.as_deref())?;
    let tempdir_path = tempdir.path().to_path_buf();
    let paths = HarnessPaths::new(tempdir.path());

    write_guest_config(&paths, scenario.config_override.as_ref())?;
    write_cloud_init(&paths)?;
    create_seed_image(&paths)?;
    create_tools_image(&paths, &collector, &victim, &agent)?;
    create_overlay_image(&opts.image, &paths.overlay_image)?;

    let mut qemu = spawn_qemu(&opts, &paths)?;
    let serial_log = SerialLogFollower::spawn(paths.serial_log.clone(), scenario.name);
    let result = (|| {
        let mut control = ControlChannel::connect(&mut qemu, &paths.control_socket, || {
            format_qemu_stderr_tail(&paths.qemu_stderr)
        })?;
        let reply = control.request(&VmTestRequest::RunScenario {
            scenario_name: scenario.name.to_string(),
            ingress_mode: scenario.ingress_mode,
            guest_setup: scenario.guest_setup.map(str::to_string),
            trigger_command: scenario.trigger_command.to_string(),
            expect_record: scenario.expect_record,
        })?;

        let (record, core_files, sqlite_present, records_jsonl) = match reply {
            VmTestReply::ScenarioResult {
                record,
                core_files,
                sqlite_present,
                records_jsonl,
            } => (record, core_files, sqlite_present, records_jsonl),
            VmTestReply::Error { message } => bail!("guest agent returned error: {message}"),
            VmTestReply::Pong => bail!("unexpected pong reply for scenario run"),
            VmTestReply::CommandResult { .. } => {
                bail!("unexpected command_result reply for scenario run")
            }
        };

        fs::create_dir_all(&paths.artifacts_dir).context("create artifacts dir")?;
        fs::write(paths.artifacts_dir.join("records.jsonl"), &records_jsonl)
            .context("write local records.jsonl")?;
        if let Some(record) = &record {
            fs::write(
                paths.artifacts_dir.join("record.json"),
                serde_json::to_vec_pretty(record).context("serialize record.json")?,
            )
            .context("write local record.json")?;
        }

        let result = CorePatternE2eResult {
            artifacts_dir: paths.artifacts_dir.clone(),
            record,
            core_files,
            sqlite_present,
            serial_log: paths.serial_log.clone(),
        };
        assert_scenario_expectations(&result, scenario)?;
        Ok(result)
    })();

    shutdown_qemu(&mut qemu);
    drop(serial_log);
    if result.is_err() && keep_workdir {
        eprintln!(
            "[vmtest {}] preserved workdir at {}",
            scenario.name,
            tempdir_path.display()
        );
        let _ = tempdir.keep();
    }
    result
}

struct HarnessPaths {
    meta_data: PathBuf,
    user_data: PathBuf,
    seed_image: PathBuf,
    tools_image: PathBuf,
    overlay_image: PathBuf,
    control_socket: PathBuf,
    serial_log: PathBuf,
    qemu_stdout: PathBuf,
    qemu_stderr: PathBuf,
    guest_config: PathBuf,
    artifacts_dir: PathBuf,
}

impl HarnessPaths {
    fn new(root: &Path) -> Self {
        Self {
            meta_data: root.join("meta-data"),
            user_data: root.join("user-data"),
            seed_image: root.join("seed.img"),
            tools_image: root.join("tools.img"),
            overlay_image: root.join("overlay.qcow2"),
            control_socket: root.join("control.sock"),
            serial_log: root.join("serial.log"),
            qemu_stdout: root.join("qemu.stdout"),
            qemu_stderr: root.join("qemu.stderr"),
            guest_config: root.join("coregate-config.json"),
            artifacts_dir: root.join("artifacts"),
        }
    }
}

fn default_collector_path() -> PathBuf {
    default_guest_binary_path("coregate")
}

fn default_victim_path() -> PathBuf {
    default_guest_binary_path("victim-crash")
}

fn default_agent_path() -> PathBuf {
    default_guest_binary_path("vmtest-agent")
}

pub fn default_guest_binary_path(name: &str) -> PathBuf {
    let musl = workspace_root()
        .join("target")
        .join(DEFAULT_GUEST_TARGET)
        .join("debug")
        .join(name);
    if musl.exists() {
        return musl;
    }

    workspace_root().join("target").join("debug").join(name)
}

fn debian_latest_dir(suite: &str) -> String {
    format!("https://cloud.debian.org/images/cloud/{suite}/latest")
}

fn debian_image_filename(suite: &str, arch: &str) -> String {
    let version = match suite {
        "bookworm" => "12",
        _ => suite,
    };
    format!("debian-{version}-generic-{arch}.qcow2")
}

fn default_debian_image_path_for(suite: &str, arch: &str) -> PathBuf {
    workspace_root()
        .join(".cache")
        .join("vm-images")
        .join(debian_image_filename(suite, arch))
}

fn debian_image_url(suite: &str, arch: &str) -> String {
    format!(
        "{}/{}",
        debian_latest_dir(suite),
        debian_image_filename(suite, arch)
    )
}

fn verify_debian_checksum(
    image_path: &Path,
    sums_path: &Path,
    suite: &str,
    arch: &str,
) -> Result<()> {
    let filename = debian_image_filename(suite, arch);
    let sums = fs::read_to_string(sums_path).context("read SHA512SUMS")?;
    let expected = sums
        .lines()
        .find_map(|line| {
            if line.ends_with(&filename) {
                line.split_whitespace().next().map(str::to_string)
            } else {
                None
            }
        })
        .with_context(|| format!("missing checksum for {filename}"))?;

    let output = run(Command::new("sha512sum").arg(image_path)).context("run sha512sum")?;
    let actual = String::from_utf8(output.stdout)
        .context("sha512sum utf8")?
        .split_whitespace()
        .next()
        .map(str::to_string)
        .context("missing sha512 value")?;

    ensure!(
        actual == expected,
        "checksum mismatch for {}",
        image_path.display()
    );
    Ok(())
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn tempdir_in(dir: Option<&Path>) -> Result<TempDir> {
    match dir {
        Some(dir) => {
            fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
            tempfile::tempdir_in(dir).with_context(|| format!("tempdir in {}", dir.display()))
        }
        None => tempfile::tempdir().context("create tempdir"),
    }
}

fn write_guest_config(paths: &HarnessPaths, override_config: Option<&Value>) -> Result<()> {
    let mut config = json!({
        "default": {
            "output_dir": "/var/lib/coregate/cores",
            "metadata_jsonl": "/var/lib/coregate/records.jsonl",
            "metadata_sqlite": "/var/lib/coregate/records.sqlite",
            "limit_state_file": "/var/lib/coregate/ratelimit.json",
            "respect_dumpable": true,
            "package_lookup": false,
            "core": {
                "compression": "zstd",
                "sparse": false
            },
            "rate_limit": {
                "default_max_per_minute": 100,
                "rules": []
            }
        }
    });
    if let Some(override_config) = override_config {
        merge_json(&mut config, override_config);
    }
    let config = serde_json::to_string_pretty(&config).context("serialize guest config")?;
    fs::write(&paths.guest_config, config).context("write guest config")?;
    Ok(())
}

fn merge_json(base: &mut Value, overlay: &Value) {
    match (base, overlay) {
        (Value::Object(base_map), Value::Object(overlay_map)) => {
            for (key, value) in overlay_map {
                merge_json(base_map.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
        (base_slot, overlay_value) => {
            *base_slot = overlay_value.clone();
        }
    }
}

fn write_run_test_cloud_init(paths: &HarnessPaths) -> Result<()> {
    fs::write(
        &paths.meta_data,
        "instance-id: coregate-vmtest\nlocal-hostname: coregate\n",
    )
    .context("write meta-data")?;

    let user_data = r#"#cloud-config
runcmd:
  - [mkdir, -p, /mnt/coregate-tools]
  - [mount, -t, vfat, -o, ro, /dev/vdc, /mnt/coregate-tools]
  - [sh, -lc, "install -m0755 /mnt/coregate-tools/* /usr/local/bin/ 2>/dev/null || true"]
  - [sh, -lc, "COREGATE_CONTROL_PORT=/dev/virtio-ports/coregate-host /usr/local/bin/vmtest-agent >/dev/console 2>&1 </dev/null &"]
"#;
    fs::write(&paths.user_data, user_data).context("write user-data")?;
    Ok(())
}

fn create_run_test_tools_image(
    paths: &HarnessPaths,
    agent: &Path,
    extra_files: &[PathBuf],
) -> Result<()> {
    run(Command::new("truncate")
        .arg("-s")
        .arg("128M")
        .arg(&paths.tools_image))
    .context("create tools image file")?;
    run(Command::new("mkfs.vfat").arg(&paths.tools_image)).context("mkfs.vfat tools image")?;
    run(Command::new("fatlabel")
        .arg(&paths.tools_image)
        .arg("COROTOOLS"))
    .context("label tools image")?;
    mcopy_into_image(&paths.tools_image, agent, "vmtest-agent")?;
    for extra in extra_files {
        let name = extra
            .file_name()
            .context("extra file has no filename")?
            .to_string_lossy();
        mcopy_into_image(&paths.tools_image, extra, &name)?;
    }
    Ok(())
}

fn write_cloud_init(paths: &HarnessPaths) -> Result<()> {
    fs::write(
        &paths.meta_data,
        "instance-id: coregate-vmtest\nlocal-hostname: coregate\n",
    )
    .context("write meta-data")?;

    let user_data = r#"#cloud-config
runcmd:
  - [mkdir, -p, /var/lib/coregate/cores]
  - [mkdir, -p, /etc/coregate]
  - [mkdir, -p, /mnt/coregate-tools]
  - [mount, -t, vfat, -o, ro, /dev/vdc, /mnt/coregate-tools]
  - [install, -m0755, /mnt/coregate-tools/coregate, /usr/local/bin/coregate]
  - [install, -m0755, /mnt/coregate-tools/victim-crash, /usr/local/bin/victim-crash]
  - [install, -m0755, /mnt/coregate-tools/vmtest-agent, /usr/local/bin/vmtest-agent]
  - [install, -m0644, /mnt/coregate-tools/coregate-config.json, /etc/coregate/config.json]
  - [sysctl, -w, kernel.core_pipe_limit=16]
  - [sh, -lc, "echo vmtest-cloudinit listing /dev/virtio-ports; ls -l /dev/virtio-ports || true; if [ -e /dev/virtio-ports/coregate-host ]; then echo vmtest-cloudinit control port present; else echo vmtest-cloudinit control port missing; fi"]
  - [sh, -lc, "COREGATE_CONTROL_PORT=/dev/virtio-ports/coregate-host /usr/local/bin/vmtest-agent >/dev/console 2>&1 </dev/null &"]
"#;
    fs::write(&paths.user_data, user_data).context("write user-data")?;
    Ok(())
}

fn create_seed_image(paths: &HarnessPaths) -> Result<()> {
    run(Command::new("truncate")
        .arg("-s")
        .arg("32M")
        .arg(&paths.seed_image))
    .context("create seed image file")?;
    run(Command::new("mkfs.vfat").arg(&paths.seed_image)).context("mkfs.vfat seed image")?;
    run(Command::new("fatlabel")
        .arg(&paths.seed_image)
        .arg("CIDATA"))
    .context("label seed image")?;
    mcopy_into_image(&paths.seed_image, &paths.meta_data, "meta-data")?;
    mcopy_into_image(&paths.seed_image, &paths.user_data, "user-data")?;
    Ok(())
}

fn create_tools_image(
    paths: &HarnessPaths,
    collector: &Path,
    victim: &Path,
    agent: &Path,
) -> Result<()> {
    run(Command::new("truncate")
        .arg("-s")
        .arg("128M")
        .arg(&paths.tools_image))
    .context("create tools image file")?;
    run(Command::new("mkfs.vfat").arg(&paths.tools_image)).context("mkfs.vfat tools image")?;
    run(Command::new("fatlabel")
        .arg(&paths.tools_image)
        .arg("COROTOOLS"))
    .context("label tools image")?;
    mcopy_into_image(&paths.tools_image, collector, "coregate")?;
    mcopy_into_image(&paths.tools_image, victim, "victim-crash")?;
    mcopy_into_image(&paths.tools_image, agent, "vmtest-agent")?;
    mcopy_into_image(
        &paths.tools_image,
        &paths.guest_config,
        "coregate-config.json",
    )?;
    Ok(())
}

fn mcopy_into_image(image: &Path, local: &Path, remote_name: &str) -> Result<()> {
    run(Command::new("mcopy")
        .arg("-oi")
        .arg(image)
        .arg(local)
        .arg(format!("::{remote_name}")))
    .with_context(|| {
        format!(
            "copy {} into {} as {remote_name}",
            local.display(),
            image.display()
        )
    })?;
    Ok(())
}

fn create_overlay_image(base: &Path, overlay: &Path) -> Result<()> {
    // qemu-img resolves relative backing paths from the overlay location, not
    // the caller's cwd. Bazel passes runfile-relative paths, so make it stable.
    let base = base
        .canonicalize()
        .with_context(|| format!("resolve backing image {}", base.display()))?;
    run(Command::new("qemu-img")
        .arg("create")
        .arg("-f")
        .arg("qcow2")
        .arg("-F")
        .arg("qcow2")
        .arg("-b")
        .arg(base)
        .arg(overlay))
    .context("create overlay image")?;
    Ok(())
}

fn spawn_qemu(opts: &CorePatternE2eOptions, paths: &HarnessPaths) -> Result<Child> {
    ensure_parent(&paths.control_socket)?;
    let stdout = fs::File::create(&paths.qemu_stdout).context("create qemu stdout log")?;
    let stderr = fs::File::create(&paths.qemu_stderr).context("create qemu stderr log")?;

    let mut cmd = Command::new("qemu-system-x86_64");
    if Path::new("/dev/kvm").exists() {
        cmd.arg("-accel").arg("kvm");
    } else {
        cmd.arg("-accel").arg("tcg");
    }
    cmd.arg("-smp")
        .arg(opts.cpus.to_string())
        .arg("-m")
        .arg(opts.memory_mib.to_string())
        .arg("-nographic")
        .arg("-serial")
        .arg(format!("file:{}", paths.serial_log.display()))
        .arg("-drive")
        .arg(format!(
            "if=virtio,format=qcow2,file={}",
            paths.overlay_image.display()
        ))
        .arg("-drive")
        .arg(format!(
            "if=virtio,format=raw,file={},readonly=on",
            paths.seed_image.display()
        ))
        .arg("-drive")
        .arg(format!(
            "if=virtio,format=raw,file={},readonly=on",
            paths.tools_image.display()
        ))
        .arg("-device")
        .arg("virtio-serial-pci")
        .arg("-chardev")
        .arg(format!(
            "socket,path={},id=coregate-control,server=on,wait=off",
            paths.control_socket.display()
        ))
        .arg("-device")
        .arg("virtserialport,chardev=coregate-control,name=coregate-host")
        .arg("-no-reboot")
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));

    if let (Some(kernel), Some(initrd)) = (&opts.kernel, &opts.initrd) {
        cmd.arg("-kernel")
            .arg(kernel)
            .arg("-initrd")
            .arg(initrd)
            .arg("-append")
            .arg(kernel_append(opts.append.as_deref()));
    }

    cmd.spawn().context("spawn qemu")
}

fn kernel_append(extra: Option<&str>) -> String {
    let base = "root=/dev/vda1 console=ttyS0";
    match extra {
        Some(extra) if !extra.trim().is_empty() => format!("{base} {extra}"),
        _ => base.to_string(),
    }
}

fn run(cmd: &mut Command) -> Result<Output> {
    let output = cmd
        .output()
        .with_context(|| format!("spawn command: {cmd:?}"))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(anyhow!(
            "command failed: {:?}\nstdout:\n{}\nstderr:\n{}",
            cmd,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn shutdown_qemu(child: &mut Child) {
    if let Ok(None) = child.try_wait() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn format_qemu_stderr_tail(path: &Path) -> String {
    match fs::read_to_string(path) {
        Ok(text) => {
            let lines = text.lines().collect::<Vec<_>>();
            if lines.is_empty() {
                String::new()
            } else {
                let start = lines.len().saturating_sub(20);
                format!(
                    "\nqemu stderr tail ({}):\n{}",
                    path.display(),
                    lines[start..].join("\n")
                )
            }
        }
        Err(_) => String::new(),
    }
}

struct SerialLogFollower {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl SerialLogFollower {
    fn spawn(path: PathBuf, scenario_name: &str) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let scenario_name = scenario_name.to_string();
        let thread = thread::spawn(move || {
            let mut offset = 0u64;
            let mut pending = String::new();

            while !stop_thread.load(Ordering::Relaxed) {
                if let Ok(mut file) = fs::File::open(&path)
                    && file.seek(SeekFrom::Start(offset)).is_ok()
                {
                    let mut buf = Vec::new();
                    if file.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
                        offset += buf.len() as u64;
                        let chunk = String::from_utf8_lossy(&buf);
                        pending.push_str(&chunk);
                        while let Some(pos) = pending.find('\n') {
                            let line = pending.drain(..=pos).collect::<String>();
                            eprintln!(
                                "[vmtest {scenario}] {}",
                                line.trim_end(),
                                scenario = scenario_name
                            );
                        }
                    }
                }
                thread::sleep(Duration::from_millis(250));
            }

            if let Ok(mut file) = fs::File::open(&path)
                && file.seek(SeekFrom::Start(offset)).is_ok()
            {
                let mut buf = Vec::new();
                if file.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
                    let chunk = String::from_utf8_lossy(&buf);
                    pending.push_str(&chunk);
                }
            }
            if !pending.trim().is_empty() {
                for line in pending.lines() {
                    eprintln!("[vmtest {scenario}] {line}", scenario = scenario_name);
                }
            }
        });

        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for SerialLogFollower {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn env_path(key: &str) -> Option<PathBuf> {
    env::var_os(key).map(PathBuf::from)
}

fn assert_scenario_expectations(
    result: &CorePatternE2eResult,
    scenario: &VmScenario<'_>,
) -> Result<()> {
    if scenario.expect_record {
        ensure!(
            result.record.is_some(),
            "expected a crash record for scenario {}",
            scenario.name
        );
    } else {
        ensure!(
            result.record.is_none(),
            "expected no crash record for scenario {}",
            scenario.name
        );
    }

    if scenario.expect_core {
        ensure!(
            !result.core_files.is_empty(),
            "expected at least one core file for scenario {}; record={}",
            scenario.name,
            result
                .record
                .as_ref()
                .map(|r| r.to_string())
                .unwrap_or_else(|| "null".to_string())
        );
    } else {
        ensure!(
            result.core_files.is_empty(),
            "expected no core files for scenario {}",
            scenario.name
        );
    }

    if scenario.expect_sqlite {
        ensure!(
            result.sqlite_present,
            "expected SQLite artifact for scenario {}",
            scenario.name
        );
    }

    if let Some(expected) = scenario.expect_rate_limit_allowed {
        let actual = result
            .record
            .as_ref()
            .and_then(|record| record["rate_limit"]["allowed"].as_bool());
        ensure!(
            actual == Some(expected),
            "unexpected rate_limit.allowed for scenario {}: expected {:?}, got {:?}",
            scenario.name,
            expected,
            actual
        );
    }

    Ok(())
}
