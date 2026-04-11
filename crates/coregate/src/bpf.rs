//! Optional BPF stack integration for `coregate`.
//!
//! The rest of the collector calls this module unconditionally. This file
//! provides real implementations when the `bpf` feature is enabled and small
//! no-BPF stubs otherwise, keeping `libbpf-sys` out of the default build.

use crate::config::EffectiveConfig;
use anyhow::Result;

#[cfg(feature = "bpf")]
pub use coregate_bpf_stack::StackRecord;

#[cfg(not(feature = "bpf"))]
pub type StackRecord = serde_json::Value;

#[cfg(feature = "bpf")]
use crate::config::EffectiveSymbolizerConfig;
#[cfg(feature = "bpf")]
use anyhow::Context;
#[cfg(feature = "bpf")]
use coregate_bpf_stack::{
    DebuginfodClient, RemoteSymbolizationResponse, apply_remote_symbolization,
    build_remote_symbolization_request, normalize_stack_record, read_pinned_stack,
    read_pinned_stats, symbolize_remote_request_with_debuginfod, symbolize_stack_record,
};
#[cfg(feature = "bpf")]
use reqwest::blocking::Client;

#[cfg(feature = "bpf")]
pub fn print_debug_stack(pid: u32, keep: bool, json: bool) -> Result<()> {
    let mut stack = read_pinned_stack(pid, !keep)
        .with_context(|| format!("read pinned BPF stack for pid {pid}"))?;

    if let Some(stack_record) = stack.as_mut()
        && let Err(err) = symbolize_stack_record(pid, stack_record)
    {
        eprintln!("coregate: failed to symbolize pinned BPF stack for pid {pid}: {err:#}");
    }

    if json {
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
            println!("no pinned BPF stack entry for pid {pid}");
        }
    }

    Ok(())
}

#[cfg(not(feature = "bpf"))]
pub fn print_debug_stack(_pid: u32, _keep: bool, _json: bool) -> Result<()> {
    anyhow::bail!("coregate was built without BPF support; rebuild with --features bpf")
}

#[cfg(feature = "bpf")]
pub fn print_debug_stats(json: bool) -> Result<()> {
    let stats = read_pinned_stats().context("read pinned BPF tracer stats")?;

    if json {
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

#[cfg(not(feature = "bpf"))]
pub fn print_debug_stats(_json: bool) -> Result<()> {
    anyhow::bail!("coregate was built without BPF support; rebuild with --features bpf")
}

#[cfg(feature = "bpf")]
pub fn read_crash_stack(config: &EffectiveConfig, pid: i32) -> (Option<StackRecord>, String) {
    match u32::try_from(pid) {
        Ok(pid) => match read_pinned_stack(pid, true) {
            Ok(mut stack) => {
                let status = if let Some(stack_record) = stack.as_mut() {
                    match symbolize_stack(config, pid, stack_record) {
                        Ok(status) => status.to_string(),
                        Err(err) => {
                            eprintln!(
                                "coregate: failed to symbolize pinned BPF stack for pid {pid}: {err:#}"
                            );
                            format!("failed:{err:#}")
                        }
                    }
                } else {
                    "no_stack".to_string()
                };
                (stack, status)
            }
            Err(err) => {
                eprintln!("coregate: failed to read pinned BPF stack for pid {pid}: {err:#}");
                (None, format!("stack_read_failed:{err:#}"))
            }
        },
        Err(_) => (None, "invalid_pid".to_string()),
    }
}

#[cfg(not(feature = "bpf"))]
pub fn read_crash_stack(_config: &EffectiveConfig, _pid: i32) -> (Option<StackRecord>, String) {
    (None, "disabled_at_build_time".to_string())
}

#[cfg(feature = "bpf")]
pub(crate) fn symbolize_stack(
    config: &EffectiveConfig,
    pid: u32,
    stack: &mut StackRecord,
) -> Result<&'static str> {
    if stack.frames.is_empty() {
        return Ok("empty_stack");
    }

    match &config.symbolizer {
        EffectiveSymbolizerConfig::None => Ok("disabled"),
        EffectiveSymbolizerConfig::Local => {
            symbolize_stack_record(pid, stack)?;
            Ok("symbolized")
        }
        EffectiveSymbolizerConfig::Debuginfod => {
            normalize_stack_record(pid, stack).context("prepare debuginfod symbolization input")?;
            let Some(client) =
                DebuginfodClient::from_env().context("initialize debuginfod client")?
            else {
                return Ok("debuginfod_unconfigured");
            };
            let request = build_remote_symbolization_request(pid, stack)
                .context("build debuginfod symbolization request")?;
            let response = symbolize_remote_request_with_debuginfod(&request, &client)
                .context("symbolize stack with debuginfod")?;
            apply_remote_symbolization(stack, response)
                .context("apply debuginfod symbolization response")?;
            Ok("symbolized")
        }
        EffectiveSymbolizerConfig::Http(http) => {
            normalize_stack_record(pid, stack).context("prepare remote symbolization input")?;
            let request = build_remote_symbolization_request(pid, stack)
                .context("build remote symbolization request")?;
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
            Ok("symbolized")
        }
    }
}

#[cfg(all(test, feature = "bpf"))]
mod tests {
    use super::*;
    use crate::config;
    use coregate_bpf_stack::{
        NormalizedFrame, RemoteSymbolizationRequest, StackFrame,
        symbolize_remote_request_with_blazesym,
    };
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;

    #[inline(never)]
    fn marker_function_for_http_test() {}

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
            assert_eq!(request.provider, "bpf");
            assert_eq!(
                request.process.as_ref().map(|process| process.pid),
                Some(std::process::id())
            );
            assert!(!request.modules.is_empty());
            assert!(
                request.frames[0]
                    .normalized
                    .as_ref()
                    .and_then(|normalized| normalized.module_id)
                    .is_some()
            );
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
                    module_id: None,
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

        symbolize_stack(&config, std::process::id(), &mut stack).unwrap();
        server.join().unwrap();

        let frame = &stack.frames[0];
        assert!(frame.symbol.is_some(), "{frame:?}");
        assert!(frame.normalized.is_some(), "{frame:?}");
    }
}
