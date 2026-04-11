use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use vmtest::{PrepareKernelOptions, RunTestOptions, fetch_debian_image, prepare_kernel, run_test};

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
    /// Run an arbitrary test binary inside a QEMU VM.
    RunTest(RunTestArgs),
    /// Install kernel packages in a guest rootfs and export kernel+initrd.
    PrepareKernel(PrepareKernelArgs),
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

    /// Kernel image for direct boot (requires --initrd).
    #[arg(long)]
    kernel: Option<PathBuf>,

    /// Initrd for direct boot (requires --kernel).
    #[arg(long)]
    initrd: Option<PathBuf>,

    /// Extra kernel command-line parameters.
    #[arg(long)]
    append: Option<String>,

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

    /// Path to a file containing guest setup shell commands.
    /// If both --guest-setup and --guest-setup-file are given,
    /// the file contents take precedence.
    #[arg(long)]
    guest_setup_file: Option<PathBuf>,

    /// Additional files to copy into the VM's /usr/local/bin/.
    #[arg(long)]
    extra_file: Vec<PathBuf>,

    /// Working directory for temporary files.
    #[arg(long)]
    workdir: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct PrepareKernelArgs {
    /// Path to the VM disk image (qcow2).
    #[arg(long)]
    image: PathBuf,

    /// Path to the vmtest-agent binary to inject into the VM.
    #[arg(long)]
    agent: PathBuf,

    /// Working directory for temporary files.
    #[arg(long)]
    workdir: Option<PathBuf>,

    /// VM memory in MiB.
    #[arg(long, default_value_t = 2048)]
    memory_mib: u32,

    /// Number of vCPUs.
    #[arg(long, default_value_t = 2)]
    cpus: u8,

    /// Ubuntu mainline tag, for example v6.19.
    #[arg(long)]
    mainline_tag: String,

    /// Kernel release, for example 6.19.0-061900-generic.
    #[arg(long)]
    kernel_release: String,

    /// Ubuntu package version suffix.
    #[arg(long)]
    package_version: String,

    /// Host output directory for vmlinuz-* and initrd.img-*.
    #[arg(long)]
    output_dir: PathBuf,
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
        Commands::RunTest(args) => {
            let guest_setup = match &args.guest_setup_file {
                Some(path) => Some(
                    std::fs::read_to_string(path)
                        .with_context(|| format!("reading guest-setup-file: {}", path.display()))?,
                ),
                None => args.guest_setup,
            };
            let result = run_test(RunTestOptions {
                image: args.image,
                kernel: args.kernel,
                initrd: args.initrd,
                append: args.append,
                agent: args.agent,
                test_binary: args.test_binary,
                memory_mib: args.memory_mib,
                cpus: args.cpus,
                timeout_secs: args.timeout,
                guest_setup,
                extra_files: args.extra_file,
                workdir: args.workdir,
            })?;
            Ok(result)
        }
        Commands::PrepareKernel(args) => {
            let paths = prepare_kernel(PrepareKernelOptions {
                image: args.image,
                agent: args.agent,
                workdir: args.workdir,
                memory_mib: args.memory_mib,
                cpus: args.cpus,
                mainline_tag: args.mainline_tag,
                kernel_release: args.kernel_release,
                package_version: args.package_version,
                output_dir: args.output_dir,
            })?;
            println!("kernel={}", paths.kernel.display());
            println!("initrd={}", paths.initrd.display());
            Ok(0)
        }
    }
}
