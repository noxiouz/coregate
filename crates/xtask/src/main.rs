use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use vmtest::{
    DEFAULT_DEBIAN_ARCH, DEFAULT_DEBIAN_SUITE, DEFAULT_GUEST_TARGET, GuestCommandOptions,
    default_debian_image_path, default_guest_binary_path, fetch_debian_image, run_guest_command,
};
use vmtest_scenarios::{scenario_names, scenario_test_filter};

#[derive(Debug, Parser)]
#[command(name = "xtask")]
#[command(about = "Developer task runner for coregate")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Vmtest(VmtestArgs),
}

#[derive(Debug, Parser)]
#[command(about = "Run QEMU-backed VM scenarios")]
struct VmtestArgs {
    #[command(subcommand)]
    command: VmtestCommand,
}

#[derive(Debug, Subcommand)]
enum VmtestCommand {
    FetchImage(FetchImageArgs),
    BuildGuestTools,
    PrepareKernel(PrepareKernelArgs),
    ListScenarios,
    Run(RunVmtestArgs),
}

#[derive(Debug, Parser)]
struct FetchImageArgs {
    #[arg(long)]
    output: Option<PathBuf>,

    #[arg(long, default_value = DEFAULT_DEBIAN_SUITE)]
    suite: String,

    #[arg(long, default_value = DEFAULT_DEBIAN_ARCH)]
    arch: String,
}

#[derive(Debug, Parser)]
struct RunVmtestArgs {
    #[arg(long)]
    image: Option<PathBuf>,

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

    #[arg(long, default_value = "all")]
    scenario: String,
}

#[derive(Debug, Parser)]
struct PrepareKernelArgs {
    #[arg(long)]
    image: Option<PathBuf>,

    #[arg(long)]
    agent: Option<PathBuf>,

    #[arg(long)]
    workdir: Option<PathBuf>,

    #[arg(long, default_value_t = 2048)]
    memory_mib: u32,

    #[arg(long, default_value_t = 2)]
    cpus: u8,

    #[arg(long, default_value = "v6.16")]
    mainline_tag: String,

    #[arg(long, default_value = "6.16.0-061600-generic")]
    kernel_release: String,

    #[arg(long, default_value = "6.16.0-061600.202507272138")]
    package_version: String,

    #[arg(long, default_value = ".cache/kernels/v6.16-mainline")]
    output_dir: PathBuf,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("xtask error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Vmtest(args) => match args.command {
            VmtestCommand::FetchImage(args) => {
                let path = fetch_debian_image(args.output, &args.suite, &args.arch)?;
                println!("{}", path.display());
                Ok(())
            }
            VmtestCommand::BuildGuestTools => build_guest_tools(),
            VmtestCommand::PrepareKernel(args) => prepare_kernel(args),
            VmtestCommand::ListScenarios => {
                for scenario in scenario_names() {
                    println!("{scenario}");
                }
                Ok(())
            }
            VmtestCommand::Run(args) => run_vmtest(args),
        },
    }
}

fn run_vmtest(args: RunVmtestArgs) -> Result<()> {
    if args.kernel.is_some() != args.initrd.is_some() {
        bail!("--kernel and --initrd must either both be set or both be unset");
    }

    let image = args.image.unwrap_or_else(default_debian_image_path);
    if !image.exists() {
        bail!(
            "VM image not found at {}. Run `cargo run -p xtask -- vmtest fetch-image` or pass --image",
            image.display()
        );
    }

    let Some(test_filter) = scenario_test_filter(&args.scenario) else {
        bail!(
            "unknown scenario '{}'; available: {}",
            args.scenario,
            scenario_names().join(", ")
        );
    };

    build_guest_tools()?;

    let mut cmd = Command::new("cargo");
    cmd.arg("test").arg("-p").arg("vmtest-scenarios");
    if let Some(test_filter) = test_filter {
        cmd.arg(test_filter);
    }
    cmd.arg("--").arg("--nocapture");

    cmd.env("COREGATE_VM_IMAGE", &image);
    cmd.env("COREGATE_VM_MEMORY_MIB", args.memory_mib.to_string());
    cmd.env("COREGATE_VM_CPUS", args.cpus.to_string());

    if let Some(kernel) = &args.kernel {
        cmd.env("COREGATE_VM_KERNEL", kernel);
    }
    if let Some(initrd) = &args.initrd {
        cmd.env("COREGATE_VM_INITRD", initrd);
    }
    if let Some(append) = &args.append {
        cmd.env("COREGATE_VM_APPEND", append);
    }
    if let Some(collector) = &args.collector {
        cmd.env("COREGATE_COLLECTOR_BIN", collector);
    }
    if let Some(victim) = &args.victim {
        cmd.env("COREGATE_VICTIM_BIN", victim);
    }
    if let Some(agent) = &args.agent {
        cmd.env("COREGATE_VMTEST_AGENT_BIN", agent);
    }
    if let Some(workdir) = &args.workdir {
        cmd.env("COREGATE_VM_WORKDIR", workdir);
    }

    let status = cmd.status().context("run cargo test for vmtest")?;
    ensure_success(status)
}

fn ensure_success(status: ExitStatus) -> Result<()> {
    if status.success() {
        return Ok(());
    }

    match status.code() {
        Some(code) => bail!("cargo test exited with status code {code}"),
        None => bail!("cargo test terminated by signal"),
    }
}

fn build_guest_tools() -> Result<()> {
    // The shipped collector binary lives in the root package, not in the
    // reusable `coregate` library crate. Build it explicitly so VM tests never
    // reuse a stale target/coregate binary from the old layout.
    let collector_status = Command::new("cargo")
        .arg("build")
        .arg("--target")
        .arg(DEFAULT_GUEST_TARGET)
        .arg("-p")
        .arg("coregate-bin")
        .arg("--bin")
        .arg("coregate")
        .env("CC_x86_64_unknown_linux_musl", "musl-gcc")
        .status()
        .context("build coregate guest binary for musl target")?;
    ensure_success(collector_status)?;

    let vmtest_status = Command::new("cargo")
        .arg("build")
        .arg("--target")
        .arg(DEFAULT_GUEST_TARGET)
        .arg("-p")
        .arg("vmtest")
        .arg("--bins")
        .env("CC_x86_64_unknown_linux_musl", "musl-gcc")
        .status()
        .context("build vmtest guest binaries for musl target")?;
    ensure_success(vmtest_status)
}

fn prepare_kernel(args: PrepareKernelArgs) -> Result<()> {
    build_guest_tools()?;

    let image = args.image.unwrap_or_else(default_debian_image_path);
    if !image.exists() {
        bail!(
            "VM image not found at {}. Run `cargo run -p xtask -- vmtest fetch-image` or pass --image",
            image.display()
        );
    }

    let agent = args
        .agent
        .clone()
        .unwrap_or_else(|| default_guest_binary_path("vmtest-agent"));

    let output_dir = if args.output_dir.is_absolute() {
        args.output_dir
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask crate dir")
            .parent()
            .expect("workspace root")
            .join(args.output_dir)
    };
    fs::create_dir_all(&output_dir).with_context(|| format!("create {}", output_dir.display()))?;

    let modules_pkg = format!(
        "linux-modules-{}_{}_amd64.deb",
        args.kernel_release, args.package_version
    );
    let image_pkg = format!(
        "linux-image-unsigned-{}_{}_amd64.deb",
        args.kernel_release, args.package_version
    );
    let kernel_release = args.kernel_release.clone();
    let mainline_tag = args.mainline_tag.clone();

    let guest_setup = format!(
        r#"
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y curl ca-certificates initramfs-tools kmod wireless-regdb
cat >> /etc/initramfs-tools/modules <<'EOF'
virtio_blk
virtio_pci
virtio_net
fat
vfat
nls_cp437
nls_iso8859_1
EOF
tmp=/root/mainline-kernel
mkdir -p "$tmp"
cd "$tmp"
base=https://kernel.ubuntu.com/mainline/{mainline_tag}/amd64
curl -fLO "$base/{modules_pkg}"
curl -fLO "$base/{image_pkg}"
dpkg -i {modules_pkg} {image_pkg}
update-initramfs -c -k {kernel_release}
test -f /boot/vmlinuz-{kernel_release}
test -f /boot/initrd.img-{kernel_release}
"#
    )
    .trim()
    .to_string();

    let dump_command = format!(
        r#"
set -euo pipefail
echo "__COREGATE_KERNEL_BEGIN__"
base64 -w0 /boot/vmlinuz-{kernel_release}
echo
echo "__COREGATE_KERNEL_END__"
echo "__COREGATE_INITRD_BEGIN__"
base64 -w0 /boot/initrd.img-{kernel_release}
echo
echo "__COREGATE_INITRD_END__"
"#
    )
    .trim()
    .to_string();

    let result = run_guest_command(GuestCommandOptions {
        image,
        kernel: None,
        initrd: None,
        append: None,
        agent,
        memory_mib: args.memory_mib,
        cpus: args.cpus,
        timeout_secs: 1800,
        guest_setup: Some(guest_setup),
        extra_files: Vec::new(),
        workdir: args.workdir,
        command: dump_command,
    })?;

    if result.exit_code != 0 {
        bail!(
            "guest prepare-kernel command failed with exit {}:\n{}",
            result.exit_code,
            result.stderr
        );
    }

    let kernel_b64 = extract_section(
        &result.stdout,
        "__COREGATE_KERNEL_BEGIN__",
        "__COREGATE_KERNEL_END__",
    )
    .context("extract kernel payload")?;
    let initrd_b64 = extract_section(
        &result.stdout,
        "__COREGATE_INITRD_BEGIN__",
        "__COREGATE_INITRD_END__",
    )
    .context("extract initrd payload")?;

    decode_base64_to_file(
        kernel_b64,
        &output_dir.join(format!("vmlinuz-{}", args.kernel_release)),
    )?;
    decode_base64_to_file(
        initrd_b64,
        &output_dir.join(format!("initrd.img-{}", args.kernel_release)),
    )?;

    println!(
        "kernel={}\ninitrd={}",
        output_dir
            .join(format!("vmlinuz-{}", args.kernel_release))
            .display(),
        output_dir
            .join(format!("initrd.img-{}", args.kernel_release))
            .display()
    );
    Ok(())
}

fn extract_section<'a>(text: &'a str, begin: &str, end: &str) -> Result<&'a str> {
    let start = text
        .find(begin)
        .with_context(|| format!("missing marker {begin}"))?;
    let after_start = &text[start + begin.len()..];
    let after_start = after_start.strip_prefix('\n').unwrap_or(after_start);
    let end_idx = after_start
        .find(end)
        .with_context(|| format!("missing marker {end}"))?;
    Ok(after_start[..end_idx].trim())
}

fn decode_base64_to_file(payload: &str, path: &std::path::Path) -> Result<()> {
    let payload_path = path.with_extension("b64.tmp");
    fs::write(&payload_path, payload)
        .with_context(|| format!("write {}", payload_path.display()))?;
    let output = Command::new("base64")
        .arg("-d")
        .arg(&payload_path)
        .output()
        .context("run base64 decoder")?;
    if !output.status.success() {
        let _ = fs::remove_file(&payload_path);
        bail!(
            "base64 decoder failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fs::write(path, output.stdout).with_context(|| format!("write {}", path.display()))?;
    fs::remove_file(&payload_path).with_context(|| format!("remove {}", payload_path.display()))?;
    Ok(())
}
