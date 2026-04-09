use anyhow::{Context, Result};
use blazesym::normalize::{Normalizer, UserMeta};
use blazesym::symbolize::source::{Process, Source};
use blazesym::symbolize::{Input, Symbolized, Symbolizer};
use blazesym::{Addr, Pid};
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use serde::{Deserialize, Serialize};
use std::mem::size_of;
use std::path::{Path, PathBuf};

pub const MAX_FRAMES: usize = 32;
pub const PIN_ROOT: &str = "/sys/fs/bpf/coregate";
pub const STACK_MAP_NAME: &str = "crash_stacks";
pub const STATS_MAP_NAME: &str = "tracer_stats";
pub const LINK_NAME: &str = "do_coredump_link";

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RawStackEntry {
    pub count: u32,
    pub reserved: u32,
    pub addrs: [u64; MAX_FRAMES],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackRecord {
    pub provider: String,
    pub frames: Vec<StackFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    pub addr: u64,
    pub symbol: Option<String>,
    pub module: Option<String>,
    pub offset: Option<u64>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u16>,
    pub reason: Option<String>,
    pub normalized: Option<NormalizedFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedFrame {
    pub kind: String,
    pub file_offset: u64,
    pub path: Option<String>,
    pub build_id: Option<String>,
    pub reason: Option<String>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct RawTracerStats {
    pub hits: u64,
    pub captured: u64,
    pub last_tgid: u32,
    pub last_count: u32,
    pub last_stack_result: i64,
    pub reserved: i64,
}

impl StackRecord {
    pub fn from_raw(provider: &str, raw: &RawStackEntry) -> Self {
        let count = usize::try_from(raw.count)
            .unwrap_or(MAX_FRAMES)
            .min(MAX_FRAMES);
        Self {
            provider: provider.to_string(),
            frames: raw.addrs[..count]
                .iter()
                .copied()
                .map(|addr| StackFrame {
                    addr,
                    symbol: None,
                    module: None,
                    offset: None,
                    file: None,
                    line: None,
                    column: None,
                    reason: None,
                    normalized: None,
                })
                .collect(),
        }
    }
}

pub fn pin_root() -> &'static Path {
    Path::new(PIN_ROOT)
}

pub fn stack_map_path() -> PathBuf {
    pin_root().join(STACK_MAP_NAME)
}

pub fn stats_map_path() -> PathBuf {
    pin_root().join(STATS_MAP_NAME)
}

pub fn link_path() -> PathBuf {
    pin_root().join(LINK_NAME)
}

pub fn symbolize_stack_record(pid: u32, stack: &mut StackRecord) -> Result<()> {
    if stack.frames.is_empty() {
        return Ok(());
    }

    let addrs = stack
        .frames
        .iter()
        .map(|frame| frame.addr as Addr)
        .collect::<Vec<_>>();
    let pid = Pid::from(pid);

    let mut errors = Vec::new();

    if let Err(err) = symbolize_live_process(pid, &addrs, stack) {
        errors.push(format!("live symbolization failed: {err:#}"));
    }
    if let Err(err) = normalize_for_remote(pid, &addrs, stack) {
        errors.push(format!("remote normalization failed: {err:#}"));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(errors.join("; "))
    }
}

pub fn read_pinned_stack(tgid: u32, delete: bool) -> Result<Option<StackRecord>> {
    let map_path = stack_map_path();
    if !map_path.exists() {
        return Ok(None);
    }

    let map = MapHandle::from_pinned_path(&map_path)
        .with_context(|| format!("open pinned map {}", map_path.display()))?;
    let key = tgid.to_ne_bytes();

    let value = if delete {
        map.lookup_and_delete(&key)
            .context("lookup_and_delete pinned stack entry")?
    } else {
        map.lookup(&key, MapFlags::empty())
            .context("lookup pinned stack entry")?
    };

    let Some(bytes) = value else {
        return Ok(None);
    };

    anyhow::ensure!(
        bytes.len() == size_of::<RawStackEntry>(),
        "unexpected BPF stack entry size: expected {}, got {}",
        size_of::<RawStackEntry>(),
        bytes.len()
    );

    let mut raw = RawStackEntry::default();
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&mut raw as *mut RawStackEntry).cast::<u8>(),
            size_of::<RawStackEntry>(),
        );
    }
    Ok(Some(StackRecord::from_raw("bpf", &raw)))
}

pub fn read_pinned_stats() -> Result<Option<RawTracerStats>> {
    let map_path = stats_map_path();
    if !map_path.exists() {
        return Ok(None);
    }

    let map = MapHandle::from_pinned_path(&map_path)
        .with_context(|| format!("open pinned stats map {}", map_path.display()))?;
    let key = 0u32.to_ne_bytes();
    let Some(bytes) = map
        .lookup(&key, MapFlags::empty())
        .context("lookup pinned tracer stats")?
    else {
        return Ok(None);
    };

    anyhow::ensure!(
        bytes.len() == size_of::<RawTracerStats>(),
        "unexpected BPF stats size: expected {}, got {}",
        size_of::<RawTracerStats>(),
        bytes.len()
    );

    let mut raw = RawTracerStats::default();
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&mut raw as *mut RawTracerStats).cast::<u8>(),
            size_of::<RawTracerStats>(),
        );
    }
    Ok(Some(raw))
}

fn symbolize_live_process(pid: Pid, addrs: &[Addr], stack: &mut StackRecord) -> Result<()> {
    let mut process = Process::new(pid);
    process.map_files = false;
    let src = Source::Process(process);
    let symbolizer = Symbolizer::new();
    let symbolized = symbolizer
        .symbolize(&src, Input::AbsAddr(addrs))
        .context("symbolize process addresses")?;

    for (frame, sym) in stack.frames.iter_mut().zip(symbolized.into_iter()) {
        match sym {
            Symbolized::Sym(sym) => {
                frame.symbol = Some(sym.name.into_owned());
                frame.module = sym
                    .module
                    .map(|module| module.to_string_lossy().into_owned());
                frame.offset = Some(sym.offset as u64);
                if let Some(info) = sym.code_info {
                    frame.file = Some(info.to_path().display().to_string());
                    frame.line = info.line;
                    frame.column = info.column;
                }
                frame.reason = None;
            }
            Symbolized::Unknown(reason) => {
                frame.reason = Some(reason.to_string());
            }
        }
    }

    Ok(())
}

fn normalize_for_remote(pid: Pid, addrs: &[Addr], stack: &mut StackRecord) -> Result<()> {
    let normalizer = Normalizer::new();
    let normalized = normalizer
        .normalize_user_addrs(pid, addrs)
        .context("normalize process addresses")?;

    for (frame, (file_offset, meta_idx)) in
        stack.frames.iter_mut().zip(normalized.outputs.into_iter())
    {
        let meta = normalized
            .meta
            .get(meta_idx)
            .with_context(|| format!("normalized meta index {} out of bounds", meta_idx))?;

        frame.normalized = Some(match meta {
            UserMeta::Elf(elf) => NormalizedFrame {
                kind: "elf".to_string(),
                file_offset,
                path: Some(elf.path.display().to_string()),
                build_id: elf
                    .build_id
                    .as_ref()
                    .map(|build_id| hex_encode(build_id.as_ref())),
                reason: None,
            },
            UserMeta::Sym(sym) => NormalizedFrame {
                kind: "sym".to_string(),
                file_offset,
                path: sym
                    .module
                    .as_ref()
                    .map(|module| module.to_string_lossy().into_owned()),
                build_id: None,
                reason: None,
            },
            UserMeta::Unknown(unknown) => NormalizedFrame {
                kind: "unknown".to_string(),
                file_offset,
                path: None,
                build_id: None,
                reason: Some(unknown.reason.to_string()),
            },
            #[allow(unreachable_patterns)]
            other => NormalizedFrame {
                kind: format!("{other:?}"),
                file_offset,
                path: None,
                build_id: None,
                reason: None,
            },
        });
    }

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[inline(never)]
    fn marker_function() {}

    #[test]
    fn symbolizes_live_process_and_normalizes_for_remote() {
        let mut stack = StackRecord {
            provider: "bpf".to_string(),
            frames: vec![StackFrame {
                addr: marker_function as *const () as usize as u64,
                symbol: None,
                module: None,
                offset: None,
                file: None,
                line: None,
                column: None,
                reason: None,
                normalized: None,
            }],
        };

        symbolize_stack_record(std::process::id(), &mut stack).unwrap();

        let frame = &stack.frames[0];
        assert!(frame.symbol.is_some(), "{frame:?}");
        assert!(frame.normalized.is_some(), "{frame:?}");
    }
}
