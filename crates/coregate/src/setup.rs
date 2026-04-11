//! Kernel `core_pattern` setup rendering and validation.
//!
//! The strings generated here are the source of truth for kernel integration.
//! Keep them aligned with the positional arguments parsed by `handle` mode.

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use std::fs;
use std::path::PathBuf;

pub(crate) const HANDLE_CORE_PATTERN_ARGS: &str = "handle %P %i %I %s %t %d %E";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/coregate/config.json";
pub(crate) const DEFAULT_SERVER_SOCKET_ADDRESS: &str = "@@/run/coregate-coredump.socket";
pub(crate) const DEFAULT_SERVER_LEGACY_SOCKET_ADDRESS: &str = "@/run/coregate-coredump.socket";

#[derive(Debug, Clone, Args)]
pub struct SetupArgs {
    #[arg(value_enum, default_value_t = SetupMode::Handle)]
    mode: SetupMode,

    #[arg(long, value_name = "PATH")]
    coregate_path: Option<PathBuf>,

    #[arg(long, value_name = "PATH", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    #[arg(long, value_name = "ADDR")]
    socket_address: Option<String>,

    #[arg(long, default_value_t = 16)]
    core_pipe_limit: u32,

    #[arg(long, value_enum, default_value_t = SetupOutput::Shell, hide = true)]
    output: SetupOutput,

    #[arg(long)]
    apply: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SetupMode {
    Handle,
    Server,
    ServerLegacy,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SetupOutput {
    Pattern,
    Sysctl,
    Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct KernelVersion {
    major: u32,
    minor: u32,
}

pub fn run_setup(args: SetupArgs) -> Result<()> {
    let coregate_path = args
        .coregate_path
        .clone()
        .or_else(default_coregate_path)
        .context("failed to detect coregate path; pass --coregate-path explicitly")?;

    ensure_setup_kernel_support(args.mode)?;

    match args.mode {
        SetupMode::Server => {
            let socket_address = args
                .socket_address
                .as_deref()
                .unwrap_or(DEFAULT_SERVER_SOCKET_ADDRESS);
            let pattern = render_server_pattern(Some(socket_address))?;
            ensure_core_pattern_len(&pattern)?;
            if args.apply {
                apply_setup(&args, &pattern)?;
                return Ok(());
            }
            let rendered = render_rendered_setup(&args, &pattern);
            println!("{rendered}");
            return Ok(());
        }
        SetupMode::ServerLegacy => {
            let socket_address = args
                .socket_address
                .as_deref()
                .unwrap_or(DEFAULT_SERVER_LEGACY_SOCKET_ADDRESS);
            let pattern = render_server_legacy_pattern(Some(socket_address))?;
            ensure_core_pattern_len(&pattern)?;
            if args.apply {
                apply_setup(&args, &pattern)?;
                return Ok(());
            }
            let rendered = render_rendered_setup(&args, &pattern);
            println!("{rendered}");
            return Ok(());
        }
        SetupMode::Handle => {}
    }

    let pattern = render_handle_pattern(&coregate_path, &args.config);
    ensure_core_pattern_len(&pattern)?;

    if args.apply {
        apply_setup(&args, &pattern)?;
        return Ok(());
    }

    let rendered = render_rendered_setup(&args, &pattern);
    println!("{rendered}");
    Ok(())
}

fn render_rendered_setup(args: &SetupArgs, pattern: &str) -> String {
    match args.output {
        SetupOutput::Pattern => pattern.to_string(),
        SetupOutput::Sysctl => render_sysctl(pattern, args),
        SetupOutput::Shell => render_shell(pattern, args),
    }
}

fn ensure_setup_kernel_support(mode: SetupMode) -> Result<()> {
    let Some(required) = required_kernel_for_setup(mode) else {
        return Ok(());
    };
    let release = current_kernel_release().context("detect running kernel release")?;
    let running = parse_kernel_version(&release)
        .with_context(|| format!("parse kernel release '{release}'"))?;
    anyhow::ensure!(
        running >= required,
        "setup mode '{}' requires Linux >= {}.{}; running kernel is {}",
        setup_mode_name(mode),
        required.major,
        required.minor,
        release
    );
    Ok(())
}

fn required_kernel_for_setup(mode: SetupMode) -> Option<KernelVersion> {
    match mode {
        SetupMode::Handle => None,
        SetupMode::ServerLegacy => Some(KernelVersion {
            major: 6,
            minor: 16,
        }),
        SetupMode::Server => Some(KernelVersion {
            major: 6,
            minor: 19,
        }),
    }
}

fn setup_mode_name(mode: SetupMode) -> &'static str {
    match mode {
        SetupMode::Handle => "handle",
        SetupMode::Server => "server",
        SetupMode::ServerLegacy => "server-legacy",
    }
}

fn current_kernel_release() -> Result<String> {
    let mut uts = unsafe { std::mem::zeroed::<libc::utsname>() };
    let rc = unsafe { libc::uname(&mut uts) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("uname");
    }
    let bytes = uts
        .release
        .iter()
        .map(|&c| c as u8)
        .take_while(|&b| b != 0)
        .collect::<Vec<u8>>();
    String::from_utf8(bytes).context("kernel release is not valid UTF-8")
}

fn parse_kernel_version(release: &str) -> Result<KernelVersion> {
    let mut parts = release.split(['.', '-']);
    let major = parts
        .next()
        .context("missing kernel major version")?
        .parse::<u32>()
        .context("parse kernel major version")?;
    let minor = parts
        .next()
        .context("missing kernel minor version")?
        .parse::<u32>()
        .context("parse kernel minor version")?;
    Ok(KernelVersion { major, minor })
}

fn render_handle_pattern(coregate_path: &std::path::Path, config: &std::path::Path) -> String {
    format!(
        "|{} {} {}",
        coregate_path.display(),
        HANDLE_CORE_PATTERN_ARGS,
        config.display()
    )
}

pub(crate) fn render_server_pattern(socket_address: Option<&str>) -> Result<String> {
    let socket_address = socket_address
        .unwrap_or(DEFAULT_SERVER_SOCKET_ADDRESS)
        .trim();
    anyhow::ensure!(
        !socket_address.is_empty(),
        "socket mode requires a non-empty --socket-address"
    );
    anyhow::ensure!(
        !socket_address.contains(char::is_whitespace),
        "socket address must not contain whitespace"
    );
    anyhow::ensure!(
        socket_address.starts_with("@@"),
        "server socket address must start with '@@' for protocol coredump mode"
    );
    Ok(socket_address.to_string())
}

pub(crate) fn render_server_legacy_pattern(socket_address: Option<&str>) -> Result<String> {
    let socket_address = socket_address
        .unwrap_or(DEFAULT_SERVER_LEGACY_SOCKET_ADDRESS)
        .trim();
    anyhow::ensure!(
        !socket_address.is_empty(),
        "socket mode requires a non-empty --socket-address"
    );
    anyhow::ensure!(
        !socket_address.contains(char::is_whitespace),
        "socket address must not contain whitespace"
    );
    anyhow::ensure!(
        socket_address.starts_with("@/"),
        "legacy server socket address must start with '@/' for legacy coredump mode"
    );
    Ok(socket_address.to_string())
}

pub(crate) fn ensure_core_pattern_len(pattern: &str) -> Result<()> {
    anyhow::ensure!(
        pattern.len() <= 127,
        "rendered core_pattern is {} bytes, kernel limit is 127 bytes: {}",
        pattern.len(),
        pattern
    );
    Ok(())
}

fn render_sysctl(pattern: &str, args: &SetupArgs) -> String {
    match args.mode {
        SetupMode::Handle | SetupMode::Server | SetupMode::ServerLegacy => format!(
            "kernel.core_pattern = {pattern}\nkernel.core_pipe_limit = {}",
            args.core_pipe_limit
        ),
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn render_shell(pattern: &str, args: &SetupArgs) -> String {
    match args.mode {
        SetupMode::Handle | SetupMode::ServerLegacy | SetupMode::Server => format!(
            "sysctl -w kernel.core_pattern={}\nsysctl -w kernel.core_pipe_limit={}",
            shell_quote(pattern),
            args.core_pipe_limit
        ),
    }
}

fn apply_setup(args: &SetupArgs, pattern: &str) -> Result<()> {
    write_sysctl("/proc/sys/kernel/core_pattern", pattern)?;
    write_sysctl(
        "/proc/sys/kernel/core_pipe_limit",
        &args.core_pipe_limit.to_string(),
    )?;
    Ok(())
}

pub(crate) fn write_sysctl(path: &str, value: &str) -> Result<()> {
    fs::write(path, value).with_context(|| format!("write {path}"))?;
    Ok(())
}

fn default_coregate_path() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_handle_setup_pattern() {
        let pattern = render_handle_pattern(
            PathBuf::from("/usr/local/bin/coregate").as_path(),
            PathBuf::from("/etc/coregate/config.json").as_path(),
        );
        assert_eq!(
            pattern,
            format!(
                "|/usr/local/bin/coregate {} /etc/coregate/config.json",
                HANDLE_CORE_PATTERN_ARGS
            )
        );
    }

    #[test]
    fn renders_server_setup_pattern() {
        let pattern = render_server_pattern(None).unwrap();
        assert_eq!(pattern, "@@/run/coregate-coredump.socket");
    }

    #[test]
    fn renders_server_legacy_setup_pattern() {
        let pattern = render_server_legacy_pattern(None).unwrap();
        assert_eq!(pattern, "@/run/coregate-coredump.socket");
    }

    #[test]
    fn renders_server_setup_pattern_in_shell_form() {
        let args = SetupArgs {
            mode: SetupMode::Server,
            coregate_path: Some(PathBuf::from("/opt/coregate/bin/coregate")),
            config: PathBuf::from("/etc/coregate/config.json"),
            socket_address: Some("@@/run/coregate-coredump.socket".to_string()),
            core_pipe_limit: 16,
            output: SetupOutput::Shell,
            apply: false,
        };
        let pattern = render_server_pattern(args.socket_address.as_deref()).unwrap();
        let rendered = render_rendered_setup(&args, &pattern);
        assert!(rendered.contains("kernel.core_pattern='@@/run/coregate-coredump.socket'"));
    }

    #[test]
    fn renders_server_legacy_setup_pattern_in_shell_form() {
        let args = SetupArgs {
            mode: SetupMode::ServerLegacy,
            coregate_path: Some(PathBuf::from("/opt/coregate/bin/coregate")),
            config: PathBuf::from("/etc/coregate/config.json"),
            socket_address: Some("@/run/coregate-coredump.socket".to_string()),
            core_pipe_limit: 16,
            output: SetupOutput::Shell,
            apply: false,
        };
        let pattern = render_server_legacy_pattern(args.socket_address.as_deref()).unwrap();
        let rendered = render_rendered_setup(&args, &pattern);
        assert!(rendered.contains("kernel.core_pattern='@/run/coregate-coredump.socket'"));
    }

    #[test]
    fn parses_kernel_version_from_release() {
        let parsed = parse_kernel_version("6.19.0-061900-generic").unwrap();
        assert_eq!(
            parsed,
            KernelVersion {
                major: 6,
                minor: 19
            }
        );
    }

    #[test]
    fn parses_kernel_version_with_distro_suffix() {
        let parsed = parse_kernel_version("6.1.0-44-amd64").unwrap();
        assert_eq!(parsed, KernelVersion { major: 6, minor: 1 });
    }

    #[test]
    fn rejects_overlong_core_pattern() {
        let pattern = format!("|/{}", "x".repeat(128));
        let err = ensure_core_pattern_len(&pattern).unwrap_err();
        assert!(err.to_string().contains("kernel limit is 127 bytes"));
    }
}
