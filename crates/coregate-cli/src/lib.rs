//! Reusable CLI front-end for Coregate binaries.
//!
//! Downstream binaries can use [`run`] when they want Coregate's kernel-facing
//! argument contract, including the exact `handle` positional order used by
//! `coregate setup`. They can still ignore this crate and build a completely
//! custom CLI on top of `crates/coregate`.

use anyhow::Result;
use clap::{Parser, Subcommand};
use coregate::Runtime;
use coregate::ingress::{ServeLegacyOptions, ServeOptions, serve, serve_legacy};
use coregate::kernel::{IngressMode, KernelDumpRequest};
use coregate::modules::{
    ConfigSource, EnricherChain, HandleRequest, Limiter, MetaExtractor, Store, Telemetry,
};
use coregate::setup::{SetupArgs, run_setup};
use std::path::PathBuf;

/// Run the standard Coregate CLI with a caller-provided runtime builder.
///
/// The builder is called for collection/server commands with the config path
/// selected by CLI arguments. `setup` is synchronous and does not start Tokio.
pub fn run<B, S, M, L, T, C, E>(build_runtime: B) -> Result<()>
where
    B: Fn(PathBuf) -> Result<Runtime<S, M, L, T, C, E>>,
    S: Store,
    M: MetaExtractor,
    L: Limiter,
    T: Telemetry,
    C: ConfigSource,
    E: EnricherChain,
{
    match Cli::parse().command {
        Commands::Setup(args) => run_setup(args),
        command => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime")
            .block_on(run_async(command, &build_runtime)),
    }
}

#[derive(Debug, Parser)]
#[command(name = "coregate")]
#[command(about = "Linux coredump collector")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Handle(HandleArgs),
    Serve(ServerArgs),
    ServeLegacy(ServerLegacyArgs),
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

    #[arg(value_name = "CONFIG", default_value = coregate::DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

#[derive(Debug, Parser)]
struct ServerArgs {
    #[arg(
        long,
        value_name = "ADDR",
        default_value = "@@/run/coregate-coredump.socket"
    )]
    socket_address: String,

    #[arg(long, value_name = "PATH", default_value = coregate::DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

#[derive(Debug, Parser)]
struct ServerLegacyArgs {
    #[arg(
        long,
        value_name = "ADDR",
        default_value = "@/run/coregate-coredump.socket"
    )]
    socket_address: String,

    #[arg(long, value_name = "PATH", default_value = coregate::DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

async fn run_async<B, S, M, L, T, C, E>(command: Commands, build_runtime: &B) -> Result<()>
where
    B: Fn(PathBuf) -> Result<Runtime<S, M, L, T, C, E>>,
    S: Store,
    M: MetaExtractor,
    L: Limiter,
    T: Telemetry,
    C: ConfigSource,
    E: EnricherChain,
{
    match command {
        Commands::Handle(args) => run_handle(args, build_runtime).await,
        Commands::Serve(args) => run_server(args, build_runtime).await,
        Commands::ServeLegacy(args) => run_server_legacy(args, build_runtime).await,
        Commands::Setup(_) => unreachable!("setup is handled before starting tokio"),
    }
}

async fn run_handle<B, S, M, L, T, C, E>(args: HandleArgs, build_runtime: &B) -> Result<()>
where
    B: Fn(PathBuf) -> Result<Runtime<S, M, L, T, C, E>>,
    S: Store,
    M: MetaExtractor,
    L: Limiter,
    T: Telemetry,
    C: ConfigSource,
    E: EnricherChain,
{
    let runtime = build_runtime(args.config)?;

    let request = HandleRequest {
        kernel: KernelDumpRequest {
            mode: IngressMode::PatternPipe,
            pid: args.pid,
            tid: args.tid,
            signal: args.signal,
            epoch_seconds: args.epoch,
            exe_hint: args.exe,
        },
        tid_initial_ns: args.tid_initial,
        dumpable_override: args.dumpable.map(|value| value != 0),
    };

    let mut stdin = tokio::io::stdin();
    runtime.handle(request, &mut stdin).await
}

async fn run_server<B, S, M, L, T, C, E>(args: ServerArgs, build_runtime: &B) -> Result<()>
where
    B: Fn(PathBuf) -> Result<Runtime<S, M, L, T, C, E>>,
    S: Store,
    M: MetaExtractor,
    L: Limiter,
    T: Telemetry,
    C: ConfigSource,
    E: EnricherChain,
{
    let runtime = build_runtime(args.config)?;
    serve(
        &runtime,
        ServeOptions {
            socket_address: args.socket_address,
        },
    )
    .await
}

async fn run_server_legacy<B, S, M, L, T, C, E>(
    args: ServerLegacyArgs,
    build_runtime: &B,
) -> Result<()>
where
    B: Fn(PathBuf) -> Result<Runtime<S, M, L, T, C, E>>,
    S: Store,
    M: MetaExtractor,
    L: Limiter,
    T: Telemetry,
    C: ConfigSource,
    E: EnricherChain,
{
    let runtime = build_runtime(args.config)?;
    serve_legacy(
        &runtime,
        ServeLegacyOptions {
            socket_address: args.socket_address,
        },
    )
    .await
}
