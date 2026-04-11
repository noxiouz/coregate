//! Socket coredump ingress implementations.
//!
//! `serve-legacy` handles the Linux 6.16 `@/path.sock` stream protocol.
//! `serve` handles the Linux 6.19 `@@/path.sock` protocol handshake before
//! streaming the core into the same collector path as `handle` mode.

use crate::kernel::{IngressMode, KernelDumpRequest};
use crate::modules::{
    ConfigSource, EnricherChain, HandleRequest, Limiter, MetaExtractor, Store, Telemetry,
};
use crate::runtime::Runtime;
use crate::setup::{
    DEFAULT_SERVER_LEGACY_SOCKET_ADDRESS, DEFAULT_SERVER_SOCKET_ADDRESS, ensure_core_pattern_len,
    render_server_legacy_pattern, render_server_pattern,
};
use anyhow::{Context, Result};
use std::fs;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

#[derive(Debug, Clone)]
pub struct ServeOptions {
    pub socket_address: String,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            socket_address: DEFAULT_SERVER_SOCKET_ADDRESS.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServeLegacyOptions {
    pub socket_address: String,
}

impl Default for ServeLegacyOptions {
    fn default() -> Self {
        Self {
            socket_address: DEFAULT_SERVER_LEGACY_SOCKET_ADDRESS.to_string(),
        }
    }
}

pub async fn serve<S, M, L, T, C, E>(
    runtime: &Runtime<S, M, L, T, C, E>,
    options: ServeOptions,
) -> Result<()>
where
    S: Store,
    M: MetaExtractor,
    L: Limiter,
    T: Telemetry,
    C: ConfigSource,
    E: EnricherChain,
{
    let socket_path = protocol_server_socket_path(&options.socket_address)?
        .context("server mode requires a socket address of the form '@@/absolute/path.sock'")?;
    let listener = bind_stream_coredump_listener(&socket_path)
        .with_context(|| format!("bind coredump listener at {}", socket_path.display()))?;
    let pattern = render_server_pattern(Some(&options.socket_address))?;
    ensure_core_pattern_len(&pattern)?;
    eprintln!(
        "coregate: listening for 6.19 coredumps on {}",
        socket_path.display()
    );
    eprintln!("coregate: kernel.core_pattern should be {}", pattern);

    loop {
        let (conn, _) = listener
            .accept()
            .await
            .context("accept coredump connection")?;
        if let Err(err) = handle_server_connection(runtime, conn).await {
            eprintln!("coregate: failed to handle coredump connection: {err:#}");
        }
    }
}

pub async fn serve_legacy<S, M, L, T, C, E>(
    runtime: &Runtime<S, M, L, T, C, E>,
    options: ServeLegacyOptions,
) -> Result<()>
where
    S: Store,
    M: MetaExtractor,
    L: Limiter,
    T: Telemetry,
    C: ConfigSource,
    E: EnricherChain,
{
    let socket_path = legacy_server_socket_path(&options.socket_address)?.context(
        "server-legacy mode requires a socket address of the form '@/absolute/path.sock'",
    )?;
    let listener = bind_stream_coredump_listener(&socket_path)
        .with_context(|| format!("bind legacy coredump listener at {}", socket_path.display()))?;
    let pattern = render_server_legacy_pattern(Some(&options.socket_address))?;
    ensure_core_pattern_len(&pattern)?;
    eprintln!(
        "coregate: listening for 6.16 coredumps on {}",
        socket_path.display()
    );
    eprintln!("coregate: kernel.core_pattern should be {}", pattern);

    loop {
        eprintln!("coregate: waiting for legacy coredump connection");
        let (conn, _) = listener
            .accept()
            .await
            .context("accept legacy coredump connection")?;
        eprintln!("coregate: accepted legacy coredump connection");
        if let Err(err) = handle_legacy_server_connection(runtime, conn).await {
            eprintln!("coregate: failed to handle legacy coredump connection: {err:#}");
        }
    }
}

async fn handle_server_connection<S, M, L, T, C, E>(
    runtime: &Runtime<S, M, L, T, C, E>,
    mut conn: UnixStream,
) -> Result<()>
where
    S: Store,
    M: MetaExtractor,
    L: Limiter,
    T: Telemetry,
    C: ConfigSource,
    E: EnricherChain,
{
    eprintln!("coregate: retrieving SO_PEERPIDFD for coredump protocol connection");
    let pidfd = peer_pidfd(conn.as_raw_fd()).context("query SO_PEERPIDFD for crashing task")?;
    let pid_info = pidfd_info(pidfd.as_raw_fd()).context("query crashing task pidfd info")?;
    let req = read_coredump_req(&mut conn)
        .await
        .context("read coredump request")?;
    validate_coredump_req(&req)?;
    send_coredump_ack(&mut conn, &req, COREDUMP_KERNEL | COREDUMP_WAIT)
        .await
        .context("send coredump ack")?;
    read_coredump_marker(&mut conn, CoredumpMark::ReqAck)
        .await
        .context("read reqack marker")?;
    let request = KernelDumpRequest {
        mode: IngressMode::Socket,
        pid: pid_info.tgid as i32,
        tid: (pid_info.pid != pid_info.tgid).then_some(pid_info.pid as i32),
        signal: coredump_signal_from_info(&pid_info),
        epoch_seconds: None,
        exe_hint: None,
    };
    runtime
        .handle(
            HandleRequest {
                kernel: request,
                tid_initial_ns: None,
                dumpable_override: Some(true),
            },
            &mut conn,
        )
        .await
}

async fn handle_legacy_server_connection<S, M, L, T, C, E>(
    runtime: &Runtime<S, M, L, T, C, E>,
    mut conn: UnixStream,
) -> Result<()>
where
    S: Store,
    M: MetaExtractor,
    L: Limiter,
    T: Telemetry,
    C: ConfigSource,
    E: EnricherChain,
{
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
    eprintln!("coregate: processing legacy coredump stream");
    runtime
        .handle(
            HandleRequest {
                kernel: request,
                tid_initial_ns: None,
                dumpable_override: Some(true),
            },
            &mut conn,
        )
        .await
}

fn legacy_server_socket_path(socket_address: &str) -> Result<Option<PathBuf>> {
    let socket_address = socket_address.trim();
    anyhow::ensure!(
        !socket_address.contains(char::is_whitespace),
        "socket address must not contain whitespace"
    );
    if let Some(path) = socket_address.strip_prefix("@/") {
        return Ok(Some(PathBuf::from(format!("/{path}"))));
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
        return Ok(Some(PathBuf::from(format!("/{path}"))));
    }
    Ok(None)
}

fn bind_stream_coredump_listener(socket_path: &Path) -> Result<UnixListener> {
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
    (|| -> Result<CoregatePidfdInfo> {
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
    })()
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

async fn read_coredump_req(conn: &mut UnixStream) -> Result<CoredumpReq> {
    let mut req = CoredumpReq {
        size: 0,
        size_ack: 0,
        mask: 0,
    };
    let req_size = size_of::<CoredumpReq>();
    let req_buf = unsafe {
        std::slice::from_raw_parts_mut((&mut req as *mut CoredumpReq).cast::<u8>(), req_size)
    };
    conn.read_exact(req_buf)
        .await
        .context("read(coredump_req)")?;
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

async fn send_coredump_ack(conn: &mut UnixStream, req: &CoredumpReq, mask: u64) -> Result<()> {
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
    conn.write_all(ack_buf)
        .await
        .context("write(coredump_ack)")?;
    Ok(())
}

async fn read_coredump_marker(conn: &mut UnixStream, expected: CoredumpMark) -> Result<()> {
    let mut byte = [0u8; 1];
    conn.read_exact(&mut byte)
        .await
        .context("read(coredump marker)")?;
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
