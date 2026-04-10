use anyhow::{Context, Result};
use blazesym::helper::read_elf_build_id;
use blazesym::normalize::{Normalizer, UserMeta};
use blazesym::symbolize::source::{Elf, Process, Source};
use blazesym::symbolize::{Input, Symbolized, Symbolizer};
use blazesym::{Addr, Pid};
pub use coregate_symbolizer_proto::symbolizer::{
    Module as RemoteModule, NormalizedFrame, ProcessInfo as RemoteProcessInfo,
    SymbolizationFrame as RemoteSymbolizationFrame,
    SymbolizationRequest as RemoteSymbolizationRequest,
    SymbolizationResponse as RemoteSymbolizationResponse, SymbolizedFrame as RemoteSymbolizedFrame,
};
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
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

pub fn normalize_stack_record(pid: u32, stack: &mut StackRecord) -> Result<()> {
    if stack.frames.is_empty() {
        return Ok(());
    }

    let addrs = stack
        .frames
        .iter()
        .map(|frame| frame.addr as Addr)
        .collect::<Vec<_>>();
    normalize_for_remote(Pid::from(pid), &addrs, stack)
}

pub fn build_remote_symbolization_request(
    pid: u32,
    stack: &StackRecord,
) -> Result<RemoteSymbolizationRequest> {
    let modules =
        collect_modules(pid).context("collect process modules for remote symbolization")?;
    let module_index = modules
        .iter()
        .map(|module| ((module.path.clone(), module.build_id.clone()), module.id))
        .collect::<HashMap<_, _>>();

    let frames = stack
        .frames
        .iter()
        .map(|frame| RemoteSymbolizationFrame {
            addr: frame.addr,
            normalized: frame.normalized.clone().map(|mut normalized| {
                if normalized.module_id.is_none() {
                    normalized.module_id = modules
                        .iter()
                        .find(|module| frame.addr >= module.start && frame.addr < module.end)
                        .map(|module| module.id)
                        .or_else(|| {
                            normalized
                                .path
                                .as_ref()
                                .map(|path| (path.clone(), normalized.build_id.clone()))
                                .and_then(|key| module_index.get(&key).copied())
                        });
                }
                normalized
            }),
        })
        .collect();

    Ok(RemoteSymbolizationRequest {
        provider: stack.provider.clone(),
        process: collect_process_info(pid),
        modules,
        frames,
    })
}

pub fn apply_remote_symbolization(
    stack: &mut StackRecord,
    response: RemoteSymbolizationResponse,
) -> Result<()> {
    anyhow::ensure!(
        stack.frames.len() == response.frames.len(),
        "remote symbolizer returned {} frames for {} inputs",
        response.frames.len(),
        stack.frames.len()
    );

    for (frame, update) in stack.frames.iter_mut().zip(response.frames.into_iter()) {
        frame.symbol = update.symbol;
        frame.module = update.module;
        frame.offset = update.offset;
        frame.file = update.file;
        frame.line = update.line;
        frame.column = update.column.and_then(|column| u16::try_from(column).ok());
        frame.reason = update.reason;
    }

    Ok(())
}

pub fn symbolize_remote_request_with_blazesym(
    request: &RemoteSymbolizationRequest,
) -> Result<RemoteSymbolizationResponse> {
    let symbolizer = Symbolizer::new();
    let mut frames = Vec::with_capacity(request.frames.len());

    for frame in &request.frames {
        let Some(normalized) = &frame.normalized else {
            frames.push(RemoteSymbolizedFrame {
                symbol: None,
                module: None,
                offset: None,
                file: None,
                line: None,
                column: None,
                reason: Some("missing_normalized_frame".to_string()),
            });
            continue;
        };

        if normalized.kind != "elf" {
            frames.push(RemoteSymbolizedFrame {
                symbol: None,
                module: None,
                offset: None,
                file: None,
                line: None,
                column: None,
                reason: Some(format!("unsupported_normalized_kind:{}", normalized.kind)),
            });
            continue;
        }

        let path = normalized
            .module_id
            .and_then(|module_id| {
                request
                    .modules
                    .iter()
                    .find(|module| module.id == module_id)
                    .map(|module| module.path.clone())
            })
            .or_else(|| normalized.path.clone());

        let Some(path) = path else {
            frames.push(RemoteSymbolizedFrame {
                symbol: None,
                module: None,
                offset: None,
                file: None,
                line: None,
                column: None,
                reason: Some("missing_normalized_path".to_string()),
            });
            continue;
        };

        let src = Source::Elf(Elf::new(path));
        match symbolizer
            .symbolize_single(&src, Input::FileOffset(normalized.file_offset))
            .context("symbolize normalized file offset")
        {
            Ok(Symbolized::Sym(sym)) => {
                let (file, line, column) = if let Some(info) = sym.code_info {
                    (
                        Some(info.to_path().display().to_string()),
                        info.line,
                        info.column.map(u32::from),
                    )
                } else {
                    (None, None, None)
                };
                frames.push(RemoteSymbolizedFrame {
                    symbol: Some(sym.name.into_owned()),
                    module: sym
                        .module
                        .map(|module| module.to_string_lossy().into_owned()),
                    offset: Some(sym.offset as u64),
                    file,
                    line,
                    column,
                    reason: None,
                });
            }
            Ok(Symbolized::Unknown(reason)) => {
                frames.push(RemoteSymbolizedFrame {
                    symbol: None,
                    module: None,
                    offset: None,
                    file: None,
                    line: None,
                    column: None,
                    reason: Some(reason.to_string()),
                });
            }
            Err(err) => {
                frames.push(RemoteSymbolizedFrame {
                    symbol: None,
                    module: None,
                    offset: None,
                    file: None,
                    line: None,
                    column: None,
                    reason: Some(err.to_string()),
                });
            }
        }
    }

    Ok(RemoteSymbolizationResponse { frames })
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
                module_id: None,
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
                module_id: None,
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
                module_id: None,
                path: None,
                build_id: None,
                reason: Some(unknown.reason.to_string()),
            },
            #[allow(unreachable_patterns)]
            other => NormalizedFrame {
                kind: format!("{other:?}"),
                file_offset,
                module_id: None,
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

fn collect_process_info(pid: u32) -> Option<RemoteProcessInfo> {
    let exe_path = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let exe_path = clean_deleted_suffix(&exe_path);
    let exe = exe_path.to_string_lossy().to_string();
    let build_id = read_elf_build_id(&exe_path)
        .ok()
        .flatten()
        .map(|build_id| hex_encode(build_id.as_ref()));
    Some(RemoteProcessInfo {
        pid,
        arch: Some(std::env::consts::ARCH.to_string()),
        exe: Some(exe),
        build_id,
    })
}

fn collect_modules(pid: u32) -> Result<Vec<RemoteModule>> {
    let raw = fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("read /proc/{pid}/maps"))?;
    let mut modules = Vec::new();
    let mut next_id = 0u32;

    for line in raw.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 6 {
            continue;
        }
        let range = fields[0];
        let perms = fields[1];
        let offset_hex = fields[2];
        let path = fields[5];

        if !path.starts_with('/') {
            continue;
        }

        let Some((start_hex, end_hex)) = range.split_once('-') else {
            continue;
        };
        let start = u64::from_str_radix(start_hex, 16).unwrap_or(0);
        let end = u64::from_str_radix(end_hex, 16).unwrap_or(0);
        let file_offset = u64::from_str_radix(offset_hex, 16).unwrap_or(0);
        let clean_path = clean_deleted_suffix(Path::new(path));
        let build_id = read_elf_build_id(&clean_path)
            .ok()
            .flatten()
            .map(|build_id| hex_encode(build_id.as_ref()));

        modules.push(RemoteModule {
            id: next_id,
            path: clean_path.to_string_lossy().to_string(),
            build_id,
            start,
            end,
            file_offset,
            perms: perms.to_string(),
        });
        next_id += 1;
    }

    Ok(modules)
}

fn clean_deleted_suffix(path: &Path) -> PathBuf {
    let rendered = path.to_string_lossy();
    PathBuf::from(rendered.strip_suffix(" (deleted)").unwrap_or(&rendered))
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

    #[test]
    fn applies_remote_symbolization_response() {
        let mut stack = StackRecord {
            provider: "bpf".to_string(),
            frames: vec![StackFrame {
                addr: 0x1234,
                symbol: None,
                module: None,
                offset: None,
                file: None,
                line: None,
                column: None,
                reason: None,
                normalized: Some(NormalizedFrame {
                    kind: "elf".to_string(),
                    file_offset: 0x44,
                    module_id: None,
                    path: Some("/bin/test".to_string()),
                    build_id: Some("deadbeef".to_string()),
                    reason: None,
                }),
            }],
        };

        apply_remote_symbolization(
            &mut stack,
            RemoteSymbolizationResponse {
                frames: vec![RemoteSymbolizedFrame {
                    symbol: Some("leaf".to_string()),
                    module: Some("/bin/test".to_string()),
                    offset: Some(4),
                    file: Some("src/main.c".to_string()),
                    line: Some(12),
                    column: Some(3),
                    reason: None,
                }],
            },
        )
        .unwrap();

        let frame = &stack.frames[0];
        assert_eq!(frame.symbol.as_deref(), Some("leaf"));
        assert_eq!(frame.module.as_deref(), Some("/bin/test"));
        assert_eq!(frame.offset, Some(4));
        assert_eq!(frame.file.as_deref(), Some("src/main.c"));
        assert_eq!(frame.line, Some(12));
        assert_eq!(frame.column, Some(3));
        assert!(frame.normalized.is_some());
    }
}
