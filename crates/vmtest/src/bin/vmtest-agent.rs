//! Guest-side agent for VM tests.
//!
//! The host sends JSON requests over virtio-serial; the agent performs setup or
//! runs crash commands inside the guest and replies with structured results.

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use vmtest::protocol::{VmIngressMode, VmTestReply, VmTestRequest};

const RECORD_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const NO_RECORD_SETTLE_TIMEOUT: Duration = Duration::from_secs(3);
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const DEFAULT_CONTROL_PORT: &str = "/dev/virtio-ports/coregate-host";

fn main() {
    if let Err(err) = run() {
        eprintln!("vmtest-agent error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let control_path =
        env::var("COREGATE_CONTROL_PORT").unwrap_or_else(|_| DEFAULT_CONTROL_PORT.to_string());
    eprintln!("vmtest-agent: starting, control path {control_path}");
    let file = open_control_port(Path::new(&control_path))?;
    eprintln!("vmtest-agent: opened control port");
    let reader_file = file.try_clone().context("clone control port fd")?;
    let mut reader = BufReader::new(reader_file);
    let mut writer = BufWriter::new(file);

    writer
        .write_all(b"BOOT_READY\n")
        .context("write boot ready notification")?;
    writer.flush().context("flush boot ready notification")?;
    eprintln!("vmtest-agent: sent BOOT_READY");

    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .context("read control request")?;
        if read == 0 {
            thread::sleep(Duration::from_millis(100));
            continue;
        }

        let request: VmTestRequest =
            serde_json::from_str(line.trim_end()).context("parse control request")?;
        eprintln!("vmtest-agent: got request");
        let reply = match request {
            VmTestRequest::Ping => VmTestReply::Pong,
            VmTestRequest::RunScenario {
                scenario_name: _,
                ingress_mode,
                guest_setup,
                trigger_command,
                expect_record,
            } => match run_scenario(
                ingress_mode,
                guest_setup.as_deref(),
                &trigger_command,
                expect_record,
            ) {
                Ok(reply) => reply,
                Err(err) => VmTestReply::Error {
                    message: format!("{err:#}"),
                },
            },
            VmTestRequest::RunCommand {
                command,
                timeout_secs: _,
            } => match run_command(&command) {
                Ok(reply) => reply,
                Err(err) => VmTestReply::Error {
                    message: format!("{err:#}"),
                },
            },
        };

        let payload = serde_json::to_vec(&reply).context("serialize control reply")?;
        writer.write_all(&payload).context("write control reply")?;
        writer
            .write_all(b"\n")
            .context("write control reply newline")?;
        writer.flush().context("flush control reply")?;
        eprintln!("vmtest-agent: wrote reply");
    }
}

fn open_control_port(path: &Path) -> Result<fs::File> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        eprintln!("vmtest-agent: opening {}", path.display());
        match fs::OpenOptions::new().read(true).write(true).open(path) {
            Ok(file) => return Ok(file),
            Err(err) => {
                eprintln!("vmtest-agent: open failed: {err}");
                if Instant::now() > deadline {
                    return Err(err)
                        .with_context(|| format!("open control port {}", path.display()));
                }
                thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

fn run_command(command: &str) -> Result<VmTestReply> {
    eprintln!("vmtest-agent: running command: {command}");
    let output = Command::new("bash")
        .arg("-lc")
        .arg(command)
        .output()
        .with_context(|| format!("run command: {command}"))?;

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    eprintln!("vmtest-agent: command exited with {exit_code}");

    Ok(VmTestReply::CommandResult {
        exit_code,
        stdout,
        stderr,
    })
}

fn run_scenario(
    ingress_mode: VmIngressMode,
    extra_setup: Option<&str>,
    command: &str,
    expect_record: bool,
) -> Result<VmTestReply> {
    let mut setup_command =
        "install -d -m0755 /etc/coregate /var/lib/coregate /var/lib/coregate/cores".to_string();
    let mut server_child = None;
    match ingress_mode {
        VmIngressMode::Handle => {
            let pattern =
                "|/usr/local/bin/coregate handle %P %i %I %s %t %d %E /etc/coregate/config.json";
            setup_command.push_str(&format!(
                " && printf '%s' '{}' > /proc/sys/kernel/core_pattern && printf '%s' '16' > /proc/sys/kernel/core_pipe_limit",
                shell_single_quote(pattern)
            ));
        }
        VmIngressMode::Server => {
            setup_command.push_str(" && rm -f /var/lib/coregate/serve.log");
        }
        VmIngressMode::ServerLegacy => {
            setup_command.push_str(" && rm -f /var/lib/coregate/serve.log");
        }
    }
    if let Some(extra_setup) = extra_setup {
        setup_command.push_str(" && ");
        setup_command.push_str(extra_setup);
    }
    run_root_shell(&setup_command).context("setup guest")?;
    if matches!(
        ingress_mode,
        VmIngressMode::Server | VmIngressMode::ServerLegacy
    ) {
        server_child = Some(start_server_mode(ingress_mode).context("start coregate serve")?);
    }
    run_crash_command(command)?;

    let result = (|| -> Result<VmTestReply> {
        let records_jsonl = wait_for_records_jsonl(expect_record)?;
        let record = if records_jsonl.trim().is_empty() {
            None
        } else {
            Some(parse_last_record(&records_jsonl)?)
        };
        let core_files = list_core_files()?;
        let sqlite_present = Path::new("/var/lib/coregate/records.sqlite").exists();

        Ok(VmTestReply::ScenarioResult {
            record,
            core_files,
            sqlite_present,
            records_jsonl,
        })
    })();
    if matches!(
        ingress_mode,
        VmIngressMode::Server | VmIngressMode::ServerLegacy
    ) {
        if let Ok(log) = fs::read_to_string("/var/lib/coregate/serve.log")
            && !log.trim().is_empty()
        {
            eprintln!("vmtest-agent: coregate serve log begin");
            eprintln!("{log}");
            eprintln!("vmtest-agent: coregate serve log end");
        }
        if let Ok(output) = Command::new("bash")
            .arg("-lc")
            .arg("dmesg | tail -n 80")
            .output()
        {
            let dmesg = String::from_utf8_lossy(&output.stdout);
            if !dmesg.trim().is_empty() {
                eprintln!("vmtest-agent: dmesg tail begin");
                eprintln!("{dmesg}");
                eprintln!("vmtest-agent: dmesg tail end");
            }
        }
    }
    if let Some(mut child) = server_child {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

fn start_server_mode(mode: VmIngressMode) -> Result<Child> {
    let _ = Command::new("pkill")
        .arg("-f")
        .arg("/usr/local/bin/coregate serve")
        .status();
    let _ = Command::new("pkill")
        .arg("-f")
        .arg("/usr/local/bin/coregate serve-legacy")
        .status();

    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/lib/coregate/serve.log")
        .context("open /var/lib/coregate/serve.log")?;
    let log_err = log
        .try_clone()
        .context("clone /var/lib/coregate/serve.log fd")?;

    let mut command = Command::new("/usr/local/bin/coregate");
    match mode {
        VmIngressMode::Server => {
            command
                .arg("serve")
                .arg("--socket-address")
                .arg("@@/run/coregate-coredump.socket");
        }
        VmIngressMode::ServerLegacy => {
            command
                .arg("serve-legacy")
                .arg("--socket-address")
                .arg("@/run/coregate-coredump.socket");
        }
        VmIngressMode::Handle => bail!("handle mode does not start a server"),
    }

    let mut child = command
        .arg("--config")
        .arg("/etc/coregate/config.json")
        .arg("--apply-sysctl")
        .arg("--core-pipe-limit")
        .arg("16")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .context("spawn coregate server")?;

    thread::sleep(Duration::from_secs(1));
    if let Some(status) = child.try_wait().context("poll coregate serve")? {
        let log = fs::read_to_string("/var/lib/coregate/serve.log").unwrap_or_default();
        bail!("coregate serve exited early with status {status}\nlog:\n{log}");
    }
    Ok(child)
}

fn run_root_shell(command: &str) -> Result<()> {
    let output = Command::new("bash")
        .arg("-lc")
        .arg(command)
        .output()
        .with_context(|| format!("run shell: {command}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "shell command failed: {command}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn run_crash_command(command: &str) -> Result<()> {
    let status = Command::new("bash")
        .arg("-lc")
        .arg(command)
        .status()
        .with_context(|| format!("run crash command: {command}"))?;
    if status.success() {
        bail!("guest command unexpectedly succeeded: {command}");
    }
    Ok(())
}

fn wait_for_records_jsonl(expect_record: bool) -> Result<String> {
    let deadline = Instant::now()
        + if expect_record {
            RECORD_WAIT_TIMEOUT
        } else {
            NO_RECORD_SETTLE_TIMEOUT
        };
    let path = "/var/lib/coregate/records.jsonl";
    loop {
        if Instant::now() > deadline {
            if expect_record {
                bail!("timed out waiting for crash record");
            }
            return Ok(String::new());
        }

        match fs::read_to_string(path) {
            Ok(text) if !text.trim().is_empty() => return Ok(text),
            _ => thread::sleep(POLL_INTERVAL),
        }
    }
}

fn parse_last_record(records_jsonl: &str) -> Result<Value> {
    let line = records_jsonl
        .lines()
        .last()
        .context("records.jsonl is empty")?;
    serde_json::from_str(line).context("parse crash record")
}

fn list_core_files() -> Result<Vec<String>> {
    let mut files = Vec::new();
    for entry in fs::read_dir("/var/lib/coregate/cores").context("read core dir")? {
        let entry = entry.context("read core dir entry")?;
        let name = entry.file_name();
        let name = name.to_string_lossy().trim().to_string();
        if !name.is_empty() {
            files.push(name);
        }
    }
    files.sort();
    Ok(files)
}

fn shell_single_quote(value: &str) -> String {
    value.replace('\'', "'\"'\"'")
}
