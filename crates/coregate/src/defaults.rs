//! Built-in module implementations used by the shipped Coregate binary.
//!
//! Downstream binaries can use some of these defaults or replace every module
//! with their own implementations through `RuntimeBuilder`.

use crate::bpf;
use crate::config::{EffectiveConfig, load_config_root, resolve_config};
use crate::corefile::{CoreWriteOptions, CoreWriteResult, write_core_async};
use crate::limit::{Decision, check_and_consume_with_file};
use crate::meta::{CrashMetadata, collect_basic, enrich_from_binary};
use crate::modules::{
    ConfigSource, Enricher, EnrichmentContext, HandleRequest, Limiter, MetaExtractor, Store,
    Telemetry, TelemetryEvent,
};
use crate::store::{CrashRecord, append_json_line, insert_sqlite_if_configured};
use anyhow::Context;
use std::path::PathBuf;
use tokio::io::AsyncRead;

#[derive(Debug, Clone)]
pub struct FileConfigSource {
    path: PathBuf,
}

impl FileConfigSource {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl ConfigSource for FileConfigSource {
    fn load(&self) -> crate::modules::BoxResultFuture<'_, crate::config::proto::ConfigRoot> {
        Box::pin(async { load_config_root(&self.path) })
    }

    fn resolve<'a>(
        &'a self,
        root: &'a crate::config::proto::ConfigRoot,
        metadata: &'a CrashMetadata,
    ) -> crate::modules::BoxResultFuture<'a, EffectiveConfig> {
        Box::pin(async { resolve_config(root, metadata) })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProcfsMeta;

impl ProcfsMeta {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ProcfsMeta {
    fn default() -> Self {
        Self::new()
    }
}

impl MetaExtractor for ProcfsMeta {
    fn extract<'a>(
        &'a self,
        request: &'a HandleRequest,
    ) -> crate::modules::BoxResultFuture<'a, CrashMetadata> {
        Box::pin(async {
            let mut metadata = collect_basic(request.kernel.pid, request.kernel.tid)
                .context("metadata collection")?;
            metadata.pid_initial_ns = Some(request.kernel.pid);
            metadata.tid_initial_ns = request.tid_initial_ns;
            metadata.signal = request.kernel.signal;
            if let Some(dumpable) = request.dumpable_override {
                metadata.dumpable = Some(dumpable);
            }
            Ok(metadata)
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LocalStore;

impl LocalStore {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LocalStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Store for LocalStore {
    fn write_core<'a>(
        &'a self,
        reader: &'a mut (dyn AsyncRead + Send + Unpin),
        options: &'a CoreWriteOptions,
    ) -> crate::modules::BoxResultFuture<'a, CoreWriteResult> {
        Box::pin(async { write_core_async(reader, options).await })
    }

    fn write_record<'a>(
        &'a self,
        config: &'a EffectiveConfig,
        record: &'a CrashRecord,
    ) -> crate::modules::BoxResultFuture<'a, ()> {
        Box::pin(async {
            append_json_line(&config.metadata_jsonl, record).context("append metadata record")?;
            insert_sqlite_if_configured(config.metadata_sqlite.as_deref(), record)
                .context("insert sqlite record")?;
            Ok(())
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PolicyLimiter;

impl PolicyLimiter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PolicyLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl Limiter for PolicyLimiter {
    fn check<'a>(
        &'a self,
        config: &'a EffectiveConfig,
        metadata: &'a CrashMetadata,
    ) -> crate::modules::BoxResultFuture<'a, Decision> {
        Box::pin(async {
            let now_epoch = chrono::Utc::now().timestamp() as u64;
            let decision = check_and_consume_with_file(
                &config.rate_limit,
                metadata.binary_name.as_deref(),
                metadata.cgroup.as_deref(),
                &config.limit_state_file,
                now_epoch,
            )?;
            Ok(decision)
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AllowAll;

impl Limiter for AllowAll {
    fn check<'a>(
        &'a self,
        _config: &'a EffectiveConfig,
        _metadata: &'a CrashMetadata,
    ) -> crate::modules::BoxResultFuture<'a, Decision> {
        Box::pin(async {
            Ok(Decision {
                allowed: true,
                reason: "allowed".to_string(),
                key: "allow_all".to_string(),
            })
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NullTelemetry;

impl Telemetry for NullTelemetry {
    fn emit(&self, _event: TelemetryEvent) {}
}

#[derive(Debug, Clone, Copy)]
pub struct BinaryMetadataEnricher;

impl Enricher for BinaryMetadataEnricher {
    fn enrich<'a>(
        &'a self,
        ctx: &'a EnrichmentContext<'_>,
        record: &'a mut CrashRecord,
    ) -> crate::modules::BoxResultFuture<'a, ()> {
        Box::pin(async {
            enrich_from_binary(&mut record.metadata, ctx.config.package_lookup);
            Ok(())
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BpfStackEnricher;

impl Enricher for BpfStackEnricher {
    fn enrich<'a>(
        &'a self,
        ctx: &'a EnrichmentContext<'_>,
        record: &'a mut CrashRecord,
    ) -> crate::modules::BoxResultFuture<'a, ()> {
        Box::pin(async {
            let (stack, symbolization_status) = bpf::read_crash_stack(ctx.config, ctx.request.pid);
            record.stack = stack;
            record.metadata.symbolization_status = Some(symbolization_status);
            Ok(())
        })
    }
}

pub fn default_enrichers() -> (BinaryMetadataEnricher, (BpfStackEnricher, ())) {
    (BinaryMetadataEnricher, (BpfStackEnricher, ()))
}
