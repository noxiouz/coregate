use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use vmtest::{CorePatternE2eOptions, RunTestOptions, fetch_debian_image, run_core_pattern_e2e, run_test};

#[derive(Debug, Parser)]
#[command(name = "vmtest")]
#[command(about = "QEMU-based integration harness for coregate")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    FetchDebianImage(FetchDebianImageArgs),
    CorePatternE2e(CorePatternArgs),
    /// Run an arbitrary test binary inside a QEMU VM.
    RunTest(RunTestArgs),
}

#[derive(Debug, Parser)]
struct FetchDebianImageArgs {
    #[arg(long)]
    output: Option<PathBuf>,

    #[arg(long, default_value = "bookworm")]
    suite: String,

    #[arg(long, default_value = "amd64")]
    arch: String,
}

#[derive(Debug, Parser)]
struct CorePatternArgs {
    #[arg(long)]
    image: PathBuf,

    #[arg(long)]
    kernel: Option<PathBuf>,

    #[arg(long)]
    initrd: Option<PathBuf>,

    #[arg(long)]
    append: Option<String>,

    #[arg(long)]
    collector: Option<PathBuf>,

    #[arg(long)]
    victim: Option<PathBuf>,

    #[arg(long)]
    agent: Option<PathBuf>,

    #[arg(long)]
    workdir: Option<PathBuf>,

    #[arg(long, default_value_t = 2048)]
    memory_mib: u32,

    #[arg(long, default_value_t = 2)]
    cpus: u8,
}

#[derive(Debug, Parser)]
struct RunTestArgs {
    /// Path to the VM disk image (qcow2).
    #[arg(long)]
    image: PathBuf,

    /// Path to the vmtest-agent binary to inject into the VM.
    #[arg(long)]
    agent: PathBuf,

    /// Path to the test binary to run inside the VM.
    #[arg(long)]
    test_binary: PathBuf,

    /// VM memory in MiB.
    #[arg(long, default_value_t = 2048)]
    memory_mib: u32,

    /// Number of vCPUs.
    #[arg(long, default_value_t = 2)]
    cpus: u8,

    /// Timeout in seconds for the test execution.
    #[arg(long, default_value_t = 300)]
    timeout: u64,

    /// Extra shell commands to run in guest before the test binary.
    #[arg(long)]
    guest_setup: Option<String>,

    /// Additional files to copy into the VM's /usr/local/bin/.
    #[arg(long)]
    extra_file: Vec<PathBuf>,

    /// Working directory for temporary files.
    #[arg(long)]
    workdir: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("vmtest error: {err:#}");
            1
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Commands::FetchDebianImage(args) => {
            let path = fetch_debian_image(args.output, &args.suite, &args.arch)?;
            println!("{}", path.display());
            Ok(0)
        }
        Commands::CorePatternE2e(args) => {
            let result = run_core_pattern_e2e(CorePatternE2eOptions {
                image: args.image,
                kernel: args.kernel,
                initrd: args.initrd,
                append: args.append,
                collector: args.collector,
                victim: args.victim,
                agent: args.agent,
                workdir: args.workdir,
                memory_mib: args.memory_mib,
                cpus: args.cpus,
            })?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(0)
        }
        Commands::RunTest(args) => {
            let result = run_test(RunTestOptions {
                image: args.image,
                agent: args.agent,
                test_binary: args.test_binary,
                memory_mib: args.memory_mib,
                cpus: args.cpus,
                timeout_secs: args.timeout,
                guest_setup: args.guest_setup,
                extra_files: args.extra_file,
                workdir: args.workdir,
            })?;
            Ok(result)
        }
    }
}
