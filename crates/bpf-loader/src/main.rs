use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use coregate_bpf_stack::{
    LINK_NAME, PIN_ROOT, STACK_MAP_NAME, STATS_MAP_NAME, link_path, pin_root, stack_map_path,
    stats_map_path,
};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use std::fs;
use std::mem::MaybeUninit;
use std::path::Path;

mod stacktrace {
    include!(concat!(env!("OUT_DIR"), "/stacktrace.skel.rs"));
}

use stacktrace::StacktraceSkelBuilder;

#[derive(Debug, Parser)]
#[command(name = "coregate-bpf")]
#[command(about = "Load and pin the coregate BPF stack tracer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Install(InstallArgs),
    Remove,
}

#[derive(Debug, Parser)]
struct InstallArgs {
    #[arg(long)]
    force: bool,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("coregate-bpf error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Install(args) => install(args),
        Commands::Remove => remove_pins(),
    }
}

fn install(args: InstallArgs) -> Result<()> {
    ensure_bpffs_mounted()?;
    fs::create_dir_all(pin_root()).with_context(|| format!("create {}", PIN_ROOT))?;

    let map_path = stack_map_path();
    let stats_path = stats_map_path();
    let link_path = link_path();
    let map_exists = map_path.exists();
    let stats_exists = stats_path.exists();
    let link_exists = link_path.exists();

    if (map_exists || stats_exists || link_exists) && !args.force {
        bail!(
            "pinned objects already exist at {}, {}, or {}; pass --force to replace them",
            map_path.display(),
            stats_path.display(),
            link_path.display()
        );
    }

    if args.force {
        remove_path_if_exists(&link_path)?;
        remove_path_if_exists(&map_path)?;
        remove_path_if_exists(&stats_path)?;
    }

    let skel_builder = StacktraceSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open = skel_builder
        .open(&mut open_object)
        .context("open BPF skeleton")?;
    let mut skel = open.load().context("load BPF object")?;

    skel.maps
        .crash_stacks
        .pin(&map_path)
        .with_context(|| format!("pin map to {}", map_path.display()))?;
    skel.maps
        .tracer_stats
        .pin(&stats_path)
        .with_context(|| format!("pin stats map to {}", stats_path.display()))?;

    skel.attach().context("attach skeleton")?;

    let link = skel
        .links
        .on_do_coredump
        .as_mut()
        .context("missing attached do_coredump link")?;
    link.pin(&link_path)
        .with_context(|| format!("pin link to {}", link_path.display()))?;

    println!("pinned map: {}", map_path.display());
    println!("pinned stats map: {}", stats_path.display());
    println!("pinned link: {}", link_path.display());
    println!("program: kprobe/do_coredump");
    println!("map: {STACK_MAP_NAME}");
    println!("stats map: {STATS_MAP_NAME}");
    println!("link: {LINK_NAME}");
    Ok(())
}

fn remove_pins() -> Result<()> {
    ensure_bpffs_mounted()?;
    remove_path_if_exists(&link_path())?;
    remove_path_if_exists(&stack_map_path())?;
    remove_path_if_exists(&stats_map_path())?;
    Ok(())
}

fn ensure_bpffs_mounted() -> Result<()> {
    let mounts = fs::read_to_string("/proc/mounts").context("read /proc/mounts")?;
    let mounted = mounts.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let _source = fields.next();
        let target = fields.next();
        let fstype = fields.next();
        target == Some("/sys/fs/bpf") && fstype == Some("bpf")
    });

    anyhow::ensure!(
        mounted,
        "/sys/fs/bpf is not mounted as bpffs; mount it first with `mount -t bpf bpffs /sys/fs/bpf`"
    );
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
    }
}
