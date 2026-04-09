mod config;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use collector_core::{Compression, CoreWriteOptions, write_core};
use collector_kernel::{IngressMode, KernelDumpRequest};
use collector_limit::{Decision, check_and_consume_with_file};
use collector_meta::{CrashMetadata, collect_basic, enrich_from_binary};
use collector_store::{CrashRecord, DumpRecord, TelemetryRecord, append_json_line};
use collector_telemetry::StageTimer;
use coregate_bpf_stack::{
    RemoteSymbolizationResponse, apply_remote_symbolization, build_remote_symbolization_request,
    normalize_stack_record, read_pinned_stack, read_pinned_stats, symbolize_stack_record,
};
use reqwest::blocking::Client;
use std::fs;
use std::io::{self, Read};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

#[cfg(feature = "sqlite")]
use collector_store::insert_sqlite;
use config::{EffectiveConfig, EffectiveSymbolizerConfig, load_config_root, resolve_config};

const HANDLE_CORE_PATTERN_ARGS: &str = "handle %P %i %I %s %t %d %E";
const DEFAULT_CONFIG_PATH: &str = "/etc/coregate/config.json";
const DEFAULT_SERVER_SOCKET_ADDRESS: &str = "@@/run/coregate-coredump.socket";
const DEFAULT_SERVER_LEGACY_SOCKET_ADDRESS: &str = "@/run/coregate-coredump.socket";

#[derive(Debug, Parser)]
#[command(name = "coregate")]
#[command(about = "Linux coredump collector MVP")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Handle(HandleArgs),
    Serve(ServeArgs),
    ServeLegacy(ServeLegacyArgs),
    DebugBpfStack(DebugBpfStackArgs),
    DebugBpfStats(DebugBpfStatsArgs),
    Setup(SetupArgs),
}

#[derive(Debug, Parser)]
struct HandleArgs {
    #[arg(value_name = "PID")]
    pid: i32,

    #[arg(value_name = "TID")]
    tid: Option<i32>,

    #[arg(value_name = "TID_INITIAL")]
    tid_initial: Option<i32>,

    #[arg(value_name = "SIGNAL")]
    signal: Option<i32>,

    #[arg(value_name = "EPOCH")]
    epoch: Option<u64>,

    #[arg(value_name = "DUMPABLE")]
    dumpable: Option<u8>,

    #[arg(value_name = "EXE")]
    exe: Option<String>,

    #[arg(value_name = "CONFIG", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

#[derive(Debug, Parser)]
struct ServeArgs {
    #[arg(long, value_name = "ADDR", default_value = DEFAULT_SERVER_SOCKET_ADDRESS)]
    socket_address: String,

    #[arg(long, value_name = "PATH", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    #[arg(long)]
    apply_sysctl: bool,

    #[arg(long, default_value_t = 16)]
    core_pipe_limit: u32,
}

#[derive(Debug, Parser)]
struct ServeLegacyArgs {
    #[arg(long, value_name = "ADDR", default_value = DEFAULT_SERVER_LEGACY_SOCKET_ADDRESS)]
    socket_address: String,

    #[arg(long, value_name = "PATH", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    #[arg(long)]
    apply_sysctl: bool,

    #[arg(long, default_value_t = 16)]
    core_pipe_limit: u32,
}

#[derive(Debug, Clone, Parser)]
struct SetupArgs {
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

#[derive(Debug, Parser)]
struct DebugBpfStackArgs {
    #[arg(value_name = "PID")]
    pid: u32,

    #[arg(long)]
    keep: bool,

    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct DebugBpfStatsArgs {
    #[arg(long)]
    json: bool,
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

fn main() {
    if let Err(err) = run() {
        eprintln!("coregate error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Handle(args) => run_handle(args),
        Commands::Serve(args) => run_serve(args),
        Commands::ServeLegacy(args) => run_serve_legacy(args),
        Commands::DebugBpfStack(args) => run_debug_bpf_stack(args),
        Commands::DebugBpfStats(args) => run_debug_bpf_stats(args),
        Commands::Setup(args) => run_setup(args),
    }
}

fn run_debug_bpf_stack(args: DebugBpfStackArgs) -> Result<()> {
    let mut stack = read_pinned_stack(args.pid, !args.keep)
        .with_context(|| format!("read pinned BPF stack for pid {}", args.pid))?;

    if let Some(stack_record) = stack.as_mut() {
        if let Err(err) = symbolize_stack_record(args.pid, stack_record) {
            eprintln!(
                "coregate: failed to symbolize pinned BPF stack for pid {}: {err:#}",
                args.pid
            );
        }
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&stack).context("serialize BPF stack")?
        );
        return Ok(());
    }

    match stack {
        Some(stack) => {
            println!("provider: {}", stack.provider);
            println!("frames: {}", stack.frames.len());
            for (idx, frame) in stack.frames.iter().enumerate() {
                match &frame.symbol {
                    Some(symbol) => println!(
                        "{idx:02}: 0x{:016x} {}{}",
                        frame.addr,
                        symbol,
                        frame
                            .offset
                            .map(|offset| format!("+0x{offset:x}"))
                            .unwrap_or_default()
                    ),
                    None => println!("{idx:02}: 0x{:016x}", frame.addr),
                }
            }
        }
        None => {
            println!("no pinned BPF stack entry for pid {}", args.pid);
        }
    }

    Ok(())
}

fn run_debug_bpf_stats(args: DebugBpfStatsArgs) -> Result<()> {
    let stats = read_pinned_stats().context("read pinned BPF tracer stats")?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&stats).context("serialize BPF tracer stats")?
        );
        return Ok(());
    }

    match stats {
        Some(stats) => {
            println!("hits: {}", stats.hits);
            println!("captured: {}", stats.captured);
            println!("last_tgid: {}", stats.last_tgid);
            println!("last_count: {}", stats.last_count);
            println!("last_stack_result: {}", stats.last_stack_result);
        }
        None => {
            println!("no pinned BPF tracer stats");
        }
    }

    Ok(())
}

fn run_setup(args: SetupArgs) -> Result<()> {
    let coregate_path = args
        .coregate_path
        .clone()
        .or_else(default_coregate_path)
        .context("failed to detect coregate path; pass --coregate-path explicitly")?;

    ensure_setup_kernel_support(args.mode)?;

    match args.mode {
        SetupMode::Server => {
            anyhow::ensure!(
                !args.apply,
                "server mode core_pattern is dynamic; run `coregate serve --apply-sysctl` instead"
            );
            let rendered = render_server_setup_command(
                &coregate_path,
                args.socket_address.as_deref(),
                &args.config,
                args.core_pipe_limit,
            )?;
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

fn run_handle(args: HandleArgs) -> Result<()> {
    let request = KernelDumpRequest {
        mode: IngressMode::PatternPipe,
        pid: args.pid,
        tid: args.tid,
        signal: args.signal,
        epoch_seconds: args.epoch,
        exe_hint: args.exe,
    };
    let mut stdin = io::stdin().lock();
    process_dump(
        request,
        args.config,
        args.tid_initial,
        args.dumpable.map(|value| value != 0),
        &mut stdin,
    )
}

fn run_serve(args: ServeArgs) -> Result<()> {
    let socket_path = protocol_server_socket_path(&args.socket_address)?
        .context("server mode requires a socket address of the form '@@/absolute/path.sock'")?;
    let listener = bind_stream_coredump_listener(&socket_path)
        .with_context(|| format!("bind coredump listener at {}", socket_path.display()))?;
    let pattern = render_server_pattern(Some(&args.socket_address))?;
    ensure_core_pattern_len(&pattern)?;
    if args.apply_sysctl {
        write_sysctl("/proc/sys/kernel/core_pattern", &pattern)?;
        write_sysctl(
            "/proc/sys/kernel/core_pipe_limit",
            &args.core_pipe_limit.to_string(),
        )?;
    }
    eprintln!(
        "coregate: listening for 6.19 coredumps on {}",
        socket_path.display()
    );
    eprintln!("coregate: kernel.core_pattern should be {}", pattern);

    loop {
        let (conn, _) = listener.accept().context("accept coredump connection")?;
        if let Err(err) = handle_server_connection(args.config.clone(), conn) {
            eprintln!("coregate: failed to handle coredump connection: {err:#}");
        }
    }
}

fn run_serve_legacy(args: ServeLegacyArgs) -> Result<()> {
    let socket_path = legacy_server_socket_path(&args.socket_address)?.context(
        "server-legacy mode requires a socket address of the form '@/absolute/path.sock'",
    )?;
    let listener = bind_stream_coredump_listener(&socket_path)
        .with_context(|| format!("bind legacy coredump listener at {}", socket_path.display()))?;
    let pattern = render_server_legacy_pattern(Some(&args.socket_address))?;
    ensure_core_pattern_len(&pattern)?;
    if args.apply_sysctl {
        write_sysctl("/proc/sys/kernel/core_pattern", &pattern)?;
        write_sysctl(
            "/proc/sys/kernel/core_pipe_limit",
            &args.core_pipe_limit.to_string(),
        )?;
    }
    eprintln!(
        "coregate: listening for 6.16 coredumps on {}",
        socket_path.display()
    );
    eprintln!("coregate: kernel.core_pattern should be {}", pattern);

    loop {
        eprintln!("coregate: waiting for legacy coredump connection");
        let (conn, _) = listener
            .accept()
            .context("accept legacy coredump connection")?;
        eprintln!("coregate: accepted legacy coredump connection");
        if let Err(err) = handle_legacy_server_connection(args.config.clone(), conn) {
            eprintln!("coregate: failed to handle legacy coredump connection: {err:#}");
        }
    }
}

fn handle_server_connection(config: PathBuf, mut conn: UnixStream) -> Result<()> {
    eprintln!("coregate: retrieving SO_PEERPIDFD for coredump protocol connection");
    let pidfd = peer_pidfd(conn.as_raw_fd()).context("query SO_PEERPIDFD for crashing task")?;
    let pid_info = pidfd_info(pidfd.as_raw_fd()).context("query crashing task pidfd info")?;
    let req = read_coredump_req(conn.as_raw_fd()).context("read coredump request")?;
    validate_coredump_req(&req)?;
    send_coredump_ack(conn.as_raw_fd(), &req, COREDUMP_KERNEL | COREDUMP_WAIT)
        .context("send coredump ack")?;
    read_coredump_marker(conn.as_raw_fd(), CoredumpMark::ReqAck).context("read reqack marker")?;
    let request = KernelDumpRequest {
        mode: IngressMode::Socket,
        pid: pid_info.tgid as i32,
        tid: (pid_info.pid != pid_info.tgid).then_some(pid_info.pid as i32),
        signal: coredump_signal_from_info(&pid_info),
        epoch_seconds: None,
        exe_hint: None,
    };
    process_dump(request, config, None, Some(true), &mut conn)
}

fn handle_legacy_server_connection(config: PathBuf, conn: UnixStream) -> Result<()> {
    eprintln!("coregate: retrieving SO_PEERPIDFD for legacy coredump connection");
    let pidfd = peer_pidfd(conn.as_raw_fd()).context("query SO_PEERPIDFD for crashing task")?;
    let pid_info = pidfd_info(pidfd.as_raw_fd()).context("query crashing task pidfd info")?;
    eprintln!(
        "coregate: legacy coredump pid info pid={} tgid={}",
        pid_info.pid, pid_info.tgid
    );
    let request = KernelDumpRequest {
        mode: IngressMode::Socket,
        pid: pid_info.tgid as i32,
        tid: (pid_info.pid != pid_info.tgid).then_some(pid_info.pid as i32),
        signal: None,
        epoch_seconds: None,
        exe_hint: None,
    };
    let mut input = conn;
    eprintln!("coregate: processing legacy coredump stream");
    process_dump(request, config, None, Some(true), &mut input)
}

fn process_dump<R: Read>(
    request: KernelDumpRequest,
    config_path: PathBuf,
    tid_initial_ns: Option<i32>,
    dumpable_override: Option<bool>,
    reader: &mut R,
) -> Result<()> {
    let mut timer = StageTimer::default();

    timer.start("load_config");
    let config_root = load_config_root(&config_path)?;
    timer.end("load_config");

    timer.start("collect_metadata");
    let mut metadata = collect_basic(request.pid, request.tid).context("metadata collection")?;
    metadata.pid_initial_ns = Some(request.pid);
    metadata.tid_initial_ns = tid_initial_ns;
    metadata.signal = request.signal;
    if let Some(dumpable) = dumpable_override {
        metadata.dumpable = Some(dumpable);
    }
    timer.end("collect_metadata");

    timer.start("resolve_config");
    let config = resolve_config(&config_root, &metadata).context("resolve config overrides")?;
    timer.end("resolve_config");

    let mut decision = if config.respect_dumpable && metadata.dumpable != Some(true) {
        Decision {
            allowed: false,
            reason: "dumpable_not_allowed".to_string(),
            key: "dumpable".to_string(),
        }
    } else {
        timer.start("rate_limit");
        let decision = evaluate_decision(&config, &metadata);
        timer.end("rate_limit");
        decision
    };

    let mut core_result = None;
    let mut dump = DumpRecord {
        stored: false,
        reason: if decision.key == "dumpable" {
            "dumpable_not_allowed".to_string()
        } else {
            "not_attempted".to_string()
        },
    };

    if decision.allowed {
        timer.start("store_core");
        let file_name = build_core_filename(request.pid, request.signal, config.core.compression);
        let core_opts = CoreWriteOptions {
            output_dir: config.output_dir.clone(),
            file_name,
            compression: config.core.compression,
            sparse: config.core.sparse,
            min_free_percent: config.core.min_free_percent,
        };

        match write_core(reader, &core_opts) {
            Ok(result) => {
                core_result = Some(result);
                dump.stored = true;
                dump.reason = "stored".to_string();
            }
            Err(err) if is_storage_reserve_refusal(&err) => {
                decision = Decision {
                    allowed: false,
                    reason: format!("storage_refused:{err}"),
                    key: "storage".to_string(),
                };
                dump.reason = "storage_refused".to_string();
            }
            Err(err) => {
                return Err(err).context("write core stream");
            }
        }
        timer.end("store_core");
    } else if dump.reason == "not_attempted" {
        dump.reason = decision.key.clone();
    }

    timer.start("enrich_metadata");
    enrich_from_binary(&mut metadata, config.package_lookup);
    timer.end("enrich_metadata");

    timer.start("bpf_stack");
    let stack = match u32::try_from(request.pid) {
        Ok(pid) => match read_pinned_stack(pid, true) {
            Ok(mut stack) => {
                if let Some(stack_record) = stack.as_mut() {
                    if let Err(err) = symbolize_bpf_stack(&config, pid, stack_record) {
                        eprintln!(
                            "coregate: failed to symbolize pinned BPF stack for pid {}: {err:#}",
                            request.pid
                        );
                    }
                }
                stack
            }
            Err(err) => {
                eprintln!(
                    "coregate: failed to read pinned BPF stack for pid {}: {err:#}",
                    request.pid
                );
                None
            }
        },
        Err(_) => None,
    };
    timer.end("bpf_stack");

    timer.start("store_record");
    let record = CrashRecord {
        schema_version: 3,
        metadata,
        stack,
        core: core_result,
        rate_limit: decision,
        dump,
        telemetry: TelemetryRecord {
            stage_ms: timer.snapshot(),
        },
    };
    append_json_line(&config.metadata_jsonl, &record).context("append metadata record")?;
    #[cfg(feature = "sqlite")]
    if let Some(path) = &config.metadata_sqlite {
        insert_sqlite(path, &record).context("insert sqlite record")?;
    }
    #[cfg(not(feature = "sqlite"))]
    if config.metadata_sqlite.is_some() {
        eprintln!("coregate: sqlite support disabled at build time; skipping metadata_sqlite sink");
    }
    timer.end("store_record");

    Ok(())
}

fn symbolize_bpf_stack(
    config: &EffectiveConfig,
    pid: u32,
    stack: &mut coregate_bpf_stack::StackRecord,
) -> Result<()> {
    match &config.symbolizer {
        EffectiveSymbolizerConfig::None => Ok(()),
        EffectiveSymbolizerConfig::Local => symbolize_stack_record(pid, stack),
        EffectiveSymbolizerConfig::Http(http) => {
            normalize_stack_record(pid, stack).context("prepare remote symbolization input")?;
            let request = build_remote_symbolization_request(stack);
            let client = Client::builder()
                .timeout(std::time::Duration::from_millis(http.timeout_ms))
                .build()
                .context("build http symbolizer client")?;
            let response = client
                .post(&http.url)
                .json(&request)
                .send()
                .and_then(|response| response.error_for_status())
                .context("send remote symbolization request")?
                .json::<RemoteSymbolizationResponse>()
                .context("decode remote symbolization response")?;
            apply_remote_symbolization(stack, response)
                .context("apply remote symbolization response")?;
            Ok(())
        }
    }
}

fn evaluate_decision(config: &EffectiveConfig, metadata: &CrashMetadata) -> Decision {
    let now_epoch = chrono::Utc::now().timestamp() as u64;
    match check_and_consume_with_file(
        &config.rate_limit,
        metadata.binary_name.as_deref(),
        metadata.cgroup.as_deref(),
        &config.limit_state_file,
        now_epoch,
    ) {
        Ok(decision) => decision,
        Err(err) => Decision {
            allowed: false,
            reason: format!("rate_limiter_error:{err}"),
            key: "rate_limiter".to_string(),
        },
    }
}

fn build_core_filename(pid: i32, signal: Option<i32>, compression: Compression) -> String {
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let sig = signal.unwrap_or(0);
    let ext = match compression {
        Compression::None => "core",
        Compression::Zstd => "core.zst",
        Compression::Xz => "core.xz",
    };
    format!("{ts}-pid{pid}-sig{sig}.{ext}")
}

fn is_storage_reserve_refusal(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .to_string()
            .contains("refusing to store core: filesystem")
    })
}

fn render_rendered_setup(args: &SetupArgs, pattern: &str) -> String {
    match args.output {
        SetupOutput::Pattern => pattern.to_string(),
        SetupOutput::Sysctl => render_sysctl(&pattern, args),
        SetupOutput::Shell => render_shell(&pattern, args),
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

fn render_server_pattern(socket_address: Option<&str>) -> Result<String> {
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

fn render_server_legacy_pattern(socket_address: Option<&str>) -> Result<String> {
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
        "legacy server socket address must start with '@/'' for legacy coredump mode"
    );
    Ok(socket_address.to_string())
}

fn ensure_core_pattern_len(pattern: &str) -> Result<()> {
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
        SetupMode::Handle => format!(
            "kernel.core_pattern = {pattern}\nkernel.core_pipe_limit = {}",
            args.core_pipe_limit
        ),
        SetupMode::Server | SetupMode::ServerLegacy => format!(
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
        SetupMode::Handle => format!(
            "sysctl -w kernel.core_pattern={}\nsysctl -w kernel.core_pipe_limit={}",
            shell_quote(pattern),
            args.core_pipe_limit
        ),
        SetupMode::Server => unreachable!("server mode setup is rendered separately"),
        SetupMode::ServerLegacy => format!(
            "sysctl -w kernel.core_pattern={}\nsysctl -w kernel.core_pipe_limit={}",
            shell_quote(pattern),
            args.core_pipe_limit
        ),
    }
}

fn apply_setup(args: &SetupArgs, pattern: &str) -> Result<()> {
    write_sysctl("/proc/sys/kernel/core_pattern", pattern)?;
    if matches!(
        args.mode,
        SetupMode::Handle | SetupMode::Server | SetupMode::ServerLegacy
    ) {
        write_sysctl(
            "/proc/sys/kernel/core_pipe_limit",
            &args.core_pipe_limit.to_string(),
        )?;
    }
    Ok(())
}

fn write_sysctl(path: &str, value: &str) -> Result<()> {
    fs::write(path, value).with_context(|| format!("write {path}"))?;
    Ok(())
}

fn default_coregate_path() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

fn legacy_server_socket_path(socket_address: &str) -> Result<Option<PathBuf>> {
    let socket_address = socket_address.trim();
    anyhow::ensure!(
        !socket_address.contains(char::is_whitespace),
        "socket address must not contain whitespace"
    );
    if let Some(path) = socket_address.strip_prefix("@/") {
        return Ok(Some(PathBuf::from(format!("/{}", path))));
    }
    Ok(None)
}

fn protocol_server_socket_path(socket_address: &str) -> Result<Option<PathBuf>> {
    let socket_address = socket_address.trim();
    anyhow::ensure!(
        !socket_address.contains(char::is_whitespace),
        "socket address must not contain whitespace"
    );
    if let Some(path) = socket_address.strip_prefix("@@/") {
        return Ok(Some(PathBuf::from(format!("/{}", path))));
    }
    Ok(None)
}

fn bind_stream_coredump_listener(socket_path: &std::path::Path) -> Result<UnixListener> {
    anyhow::ensure!(
        socket_path.is_absolute(),
        "coredump socket path must be absolute"
    );
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent directory {}", parent.display()))?;
    }
    match fs::remove_file(socket_path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("remove stale socket {}", socket_path.display()));
        }
    }
    UnixListener::bind(socket_path).with_context(|| format!("bind {}", socket_path.display()))
}

fn peer_pidfd(fd: RawFd) -> Result<OwnedFd> {
    let mut pidfd: RawFd = -1;
    let mut len = size_of::<RawFd>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            &mut pidfd as *mut RawFd as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("getsockopt(SO_PEERPIDFD)");
    }
    anyhow::ensure!(pidfd >= 0, "kernel returned invalid SO_PEERPIDFD");
    Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
}

fn render_server_setup_command(
    coregate_path: &std::path::Path,
    socket_address: Option<&str>,
    config: &std::path::Path,
    core_pipe_limit: u32,
) -> Result<String> {
    let socket_address = socket_address
        .unwrap_or(DEFAULT_SERVER_SOCKET_ADDRESS)
        .trim();
    anyhow::ensure!(
        socket_address.starts_with("@@/"),
        "server socket address must start with '@@/' for protocol coredump mode"
    );
    Ok(format!(
        "# Linux >= 6.19 required\n{} serve --socket-address {} --config {} --apply-sysctl --core-pipe-limit {}",
        shell_quote(&coregate_path.display().to_string()),
        shell_quote(socket_address),
        shell_quote(&config.display().to_string()),
        core_pipe_limit
    ))
}

#[repr(C)]
struct CoregatePidfdInfo {
    mask: u64,
    cgroupid: u64,
    pid: u32,
    tgid: u32,
    ppid: u32,
    ruid: u32,
    rgid: u32,
    euid: u32,
    egid: u32,
    suid: u32,
    sgid: u32,
    fsuid: u32,
    fsgid: u32,
    exit_code: i32,
    coredump_mask: u64,
    coredump_signal: u32,
}

const PIDFD_INFO_PID: u64 = 1 << 0;
const PIDFD_INFO_CREDS: u64 = 1 << 1;
const PIDFD_INFO_EXIT: u64 = 1 << 3;
const PIDFD_INFO_COREDUMP: u64 = 1 << 4;

fn pidfd_info(pidfd: RawFd) -> Result<CoregatePidfdInfo> {
    let result = (|| -> Result<CoregatePidfdInfo> {
        let mut info = CoregatePidfdInfo {
            mask: PIDFD_INFO_PID | PIDFD_INFO_CREDS | PIDFD_INFO_EXIT | PIDFD_INFO_COREDUMP,
            cgroupid: 0,
            pid: 0,
            tgid: 0,
            ppid: 0,
            ruid: 0,
            rgid: 0,
            euid: 0,
            egid: 0,
            suid: 0,
            sgid: 0,
            fsuid: 0,
            fsgid: 0,
            exit_code: 0,
            coredump_mask: 0,
            coredump_signal: 0,
        };
        let rc = unsafe { libc::ioctl(pidfd, libc::PIDFD_GET_INFO, &mut info) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("ioctl(PIDFD_GET_INFO)");
        }
        Ok(info)
    })();
    result
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct CoredumpReq {
    size: u32,
    size_ack: u32,
    mask: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct CoredumpAck {
    size: u32,
    spare: u32,
    mask: u64,
}

const COREDUMP_KERNEL: u64 = 1 << 0;
const COREDUMP_USERSPACE: u64 = 1 << 1;
const COREDUMP_REJECT: u64 = 1 << 2;
const COREDUMP_WAIT: u64 = 1 << 3;
const COREDUMP_REQ_SIZE_VER0: u32 = 16;
const COREDUMP_ACK_SIZE_VER0: u32 = 16;

#[allow(dead_code)]
#[derive(Clone, Copy)]
enum CoredumpMark {
    ReqAck = 0,
    MinSize = 1,
    MaxSize = 2,
    Unsupported = 3,
    Conflicting = 4,
}

fn read_coredump_req(fd: RawFd) -> Result<CoredumpReq> {
    let mut req = CoredumpReq {
        size: 0,
        size_ack: 0,
        mask: 0,
    };
    let mut read_total = 0usize;
    let req_size = size_of::<CoredumpReq>();
    let req_buf = unsafe {
        std::slice::from_raw_parts_mut((&mut req as *mut CoredumpReq).cast::<u8>(), req_size)
    };
    while read_total < req_size {
        let n = unsafe {
            libc::read(
                fd,
                req_buf[read_total..].as_mut_ptr().cast::<libc::c_void>(),
                req_size - read_total,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error()).context("read(coredump_req)");
        }
        if n == 0 {
            anyhow::bail!("unexpected EOF while reading coredump_req");
        }
        read_total += n as usize;
    }
    Ok(req)
}

fn validate_coredump_req(req: &CoredumpReq) -> Result<()> {
    anyhow::ensure!(
        req.size >= COREDUMP_REQ_SIZE_VER0 && req.size as usize <= size_of::<CoredumpReq>(),
        "unsupported coredump_req size {}",
        req.size
    );
    anyhow::ensure!(
        req.size_ack >= COREDUMP_ACK_SIZE_VER0 && req.size_ack as usize >= size_of::<CoredumpAck>(),
        "unsupported coredump_ack size advertised by kernel: {}",
        req.size_ack
    );
    let required = COREDUMP_KERNEL | COREDUMP_USERSPACE | COREDUMP_REJECT | COREDUMP_WAIT;
    anyhow::ensure!(
        (req.mask & required) == required,
        "kernel coredump protocol mask missing required bits: 0x{:x}",
        req.mask
    );
    Ok(())
}

fn send_coredump_ack(fd: RawFd, req: &CoredumpReq, mask: u64) -> Result<()> {
    anyhow::ensure!(
        (mask & !req.mask) == 0,
        "requested coredump ack mask 0x{mask:x} exceeds kernel-supported mask 0x{:x}",
        req.mask
    );
    let ack = CoredumpAck {
        size: COREDUMP_ACK_SIZE_VER0,
        spare: 0,
        mask,
    };
    let ack_buf = unsafe {
        std::slice::from_raw_parts(
            (&ack as *const CoredumpAck).cast::<u8>(),
            size_of::<CoredumpAck>(),
        )
    };
    let mut written = 0usize;
    while written < ack_buf.len() {
        let n = unsafe {
            libc::write(
                fd,
                ack_buf[written..].as_ptr().cast::<libc::c_void>(),
                ack_buf.len() - written,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error()).context("write(coredump_ack)");
        }
        if n == 0 {
            anyhow::bail!("unexpected short write for coredump_ack");
        }
        written += n as usize;
    }
    Ok(())
}

fn read_coredump_marker(fd: RawFd, expected: CoredumpMark) -> Result<()> {
    let mut byte = [0u8; 1];
    let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast::<libc::c_void>(), 1) };
    if n < 0 {
        return Err(std::io::Error::last_os_error()).context("read(coredump marker)");
    }
    anyhow::ensure!(n == 1, "missing coredump marker");
    anyhow::ensure!(
        byte[0] == expected as u8,
        "unexpected coredump marker {}, expected {}",
        byte[0],
        expected as u8
    );
    Ok(())
}

fn coredump_signal_from_info(info: &CoregatePidfdInfo) -> Option<i32> {
    const PIDFD_INFO_COREDUMP_SIGNAL: u64 = 1 << 5;
    if (info.mask & PIDFD_INFO_COREDUMP_SIGNAL) != 0 {
        Some(info.coredump_signal as i32)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coregate_bpf_stack::{
        NormalizedFrame, RemoteSymbolizationRequest, StackFrame, StackRecord,
        symbolize_remote_request_with_blazesym,
    };
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::thread;

    #[inline(never)]
    fn marker_function_for_http_test() {}

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
    fn renders_server_setup_command_with_explicit_coregate_path() {
        let rendered = render_server_setup_command(
            PathBuf::from("/opt/coregate/bin/coregate").as_path(),
            Some("@@/run/coregate-coredump.socket"),
            PathBuf::from("/etc/coregate/config.json").as_path(),
            16,
        )
        .unwrap();
        assert!(rendered.contains("'/opt/coregate/bin/coregate' serve"));
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

    #[test]
    fn http_symbolizer_wraps_blazesym() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut content_length = 0usize;

            let header_end = loop {
                let mut chunk = [0u8; 1024];
                let n = stream.read(&mut chunk).unwrap();
                assert!(n > 0);
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header_end = pos + 4;
                    let headers = std::str::from_utf8(&buf[..pos + 4]).unwrap();
                    for line in headers.lines() {
                        let lower = line.to_ascii_lowercase();
                        if let Some(value) = lower.strip_prefix("content-length:") {
                            content_length = value.trim().parse::<usize>().unwrap();
                        }
                    }
                    break header_end;
                }
            };
            while buf.len() < header_end + content_length {
                let mut chunk = [0u8; 1024];
                let n = stream.read(&mut chunk).unwrap();
                assert!(n > 0);
                buf.extend_from_slice(&chunk[..n]);
            }

            let body = &buf[header_end..header_end + content_length];
            let request: RemoteSymbolizationRequest = serde_json::from_slice(body).unwrap();
            let response = symbolize_remote_request_with_blazesym(&request).unwrap();
            let payload = serde_json::to_vec(&response).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            )
            .unwrap();
            stream.write_all(&payload).unwrap();
        });

        let mut stack = StackRecord {
            provider: "bpf".to_string(),
            frames: vec![StackFrame {
                addr: marker_function_for_http_test as *const () as usize as u64,
                symbol: None,
                module: None,
                offset: None,
                file: None,
                line: None,
                column: None,
                reason: None,
                normalized: Some(NormalizedFrame {
                    kind: "elf".to_string(),
                    file_offset: 0,
                    path: None,
                    build_id: None,
                    reason: None,
                }),
            }],
        };

        coregate_bpf_stack::normalize_stack_record(std::process::id(), &mut stack).unwrap();

        let mut config = EffectiveConfig::default();
        config.symbolizer =
            config::EffectiveSymbolizerConfig::Http(config::EffectiveHttpSymbolizerConfig {
                url: format!("http://{addr}/symbolize"),
                timeout_ms: 3_000,
            });

        symbolize_bpf_stack(&config, std::process::id(), &mut stack).unwrap();
        server.join().unwrap();

        let frame = &stack.frames[0];
        assert!(frame.symbol.is_some(), "{frame:?}");
        assert!(frame.normalized.is_some(), "{frame:?}");
    }
}
