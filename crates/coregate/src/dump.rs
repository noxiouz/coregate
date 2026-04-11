//! Compatibility shim for the older internal coredump entry point.
//!
//! New binary code should construct a `Runtime` explicitly. Server ingress uses
//! this shim until those modes are ported to the builder-backed runtime API.

use crate::defaults::{FileConfigSource, LocalStore, PolicyLimiter, ProcfsMeta, default_enrichers};
use crate::kernel::KernelDumpRequest;
use crate::modules::HandleRequest;
use crate::runtime::Runtime;
use anyhow::Result;
use std::io::{self, Read};
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

pub(crate) fn process_dump<R: Read + Send>(
    request: KernelDumpRequest,
    config_path: PathBuf,
    tid_initial_ns: Option<i32>,
    dumpable_override: Option<bool>,
    reader: &mut R,
) -> Result<()> {
    let runtime = Runtime::builder()
        .with_config(FileConfigSource::new(config_path))
        .with_meta(ProcfsMeta::new())
        .with_store(LocalStore::new())
        .with_limiter(PolicyLimiter::new())
        .with_enrichers(default_enrichers())
        .build()?;
    let mut reader = SyncReadAdapter { inner: reader };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(runtime.handle(
            HandleRequest {
                kernel: request,
                tid_initial_ns,
                dumpable_override,
            },
            &mut reader,
        ))
}

struct SyncReadAdapter<'a, R: Read + ?Sized> {
    inner: &'a mut R,
}

impl<R: Read + ?Sized> AsyncRead for SyncReadAdapter<'_, R> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.inner.read(buf.initialize_unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}
