//! Public module traits used to assemble a Coregate runtime.
//!
//! These traits are the extension surface for downstream binaries. The default
//! binary uses the implementations in `defaults`, but embedders can provide
//! their own implementations and still reuse the kernel-facing runtime flow.

use crate::config::{EffectiveConfig, proto};
use crate::corefile::{CoreWriteOptions, CoreWriteResult};
use crate::kernel::KernelDumpRequest;
use crate::limit::Decision;
use crate::meta::CrashMetadata;
use crate::store::CrashRecord;
use anyhow::Result;
use std::future::Future;
use std::pin::Pin;
use tokio::io::AsyncRead;

pub type BoxResultFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Storage backend for core streams and crash records.
///
/// Implement this to redirect captured cores and metadata to a different
/// destination, such as object storage or a database-backed record sink.
pub trait Store: Send + Sync + 'static {
    fn write_core<'a>(
        &'a self,
        reader: &'a mut (dyn AsyncRead + Send + Unpin),
        options: &'a CoreWriteOptions,
    ) -> BoxResultFuture<'a, CoreWriteResult>;

    fn write_record<'a>(
        &'a self,
        config: &'a EffectiveConfig,
        record: &'a CrashRecord,
    ) -> BoxResultFuture<'a, ()>;
}

/// Converts a kernel ingress event into the initial crash metadata record.
pub trait MetaExtractor: Send + Sync + 'static {
    fn extract<'a>(&'a self, request: &'a HandleRequest) -> BoxResultFuture<'a, CrashMetadata>;
}

/// Admission policy for deciding whether a core stream should be stored.
pub trait Limiter: Send + Sync + 'static {
    fn check<'a>(
        &'a self,
        config: &'a EffectiveConfig,
        metadata: &'a CrashMetadata,
    ) -> BoxResultFuture<'a, Decision>;
}

/// Runtime event sink for metrics or structured logging.
pub trait Telemetry: Send + Sync + 'static {
    fn emit(&self, event: TelemetryEvent);
}

/// Configuration loader and resolver.
///
/// Implementations can load from a file, an embedded value, or a remote
/// control plane, but the runtime only sees the resolved effective config.
pub trait ConfigSource: Send + Sync + 'static {
    fn load(&self) -> BoxResultFuture<'_, proto::ConfigRoot>;
    fn resolve<'a>(
        &'a self,
        root: &'a proto::ConfigRoot,
        metadata: &'a CrashMetadata,
    ) -> BoxResultFuture<'a, EffectiveConfig>;
}

/// Post-storage transformer for crash records.
///
/// Enrichers run after the core stream has been drained so expensive work does
/// not extend the kernel-facing core delivery path.
pub trait Enricher: Send + Sync + 'static {
    fn enrich<'a>(
        &'a self,
        ctx: &'a EnrichmentContext<'_>,
        record: &'a mut CrashRecord,
    ) -> BoxResultFuture<'a, ()>;
}

/// Static chain of record enrichers.
///
/// Tuple implementations make the common path statically dispatched while
/// still allowing downstream binaries to pick their own ordered stages.
pub trait EnricherChain: Send + Sync + 'static {
    fn run<'a>(
        &'a self,
        ctx: &'a EnrichmentContext<'_>,
        record: &'a mut CrashRecord,
    ) -> BoxResultFuture<'a, ()>;
}

impl EnricherChain for () {
    fn run<'a>(
        &'a self,
        _ctx: &'a EnrichmentContext<'_>,
        _record: &'a mut CrashRecord,
    ) -> BoxResultFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

impl<A, B> EnricherChain for (A, B)
where
    A: Enricher,
    B: EnricherChain,
{
    fn run<'a>(
        &'a self,
        ctx: &'a EnrichmentContext<'_>,
        record: &'a mut CrashRecord,
    ) -> BoxResultFuture<'a, ()> {
        Box::pin(async move {
            self.0.enrich(ctx, record).await?;
            self.1.run(ctx, record).await
        })
    }
}

#[derive(Debug, Clone)]
pub struct HandleRequest {
    pub kernel: KernelDumpRequest,
    pub tid_initial_ns: Option<i32>,
    pub dumpable_override: Option<bool>,
}

pub struct EnrichmentContext<'a> {
    pub config: &'a EffectiveConfig,
    pub request: &'a KernelDumpRequest,
}

#[derive(Debug, Clone)]
pub struct TelemetryEvent {
    pub name: String,
}
