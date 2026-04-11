//! Runtime and type-state builder for composing Coregate modules.
//!
//! The runtime owns concrete module values and uses static dispatch. This keeps
//! the hot path free of vtables while letting downstream binaries build their
//! own Coregate composition.

use crate::config::{EffectiveConfig, EffectiveSymbolizerConfig};
use crate::corefile::{Compression, CoreWriteOptions};
use crate::defaults::{AllowAll, NullTelemetry};
use crate::limit::Decision;
use crate::modules::{
    ConfigSource, EnricherChain, EnrichmentContext, HandleRequest, Limiter, MetaExtractor, Store,
    Telemetry, TelemetryEvent,
};
use crate::store::{CrashRecord, DumpRecord, TelemetryRecord};
use crate::telemetry::StageTimer;
use anyhow::{Context, Result};
use tokio::io::AsyncRead;

/// Type-state marker used for required builder slots that have not been set.
pub struct Missing;

/// Coregate runtime assembled from concrete module implementations.
pub struct Runtime<S, M, L, T, C, E> {
    store: S,
    meta: M,
    limiter: L,
    telemetry: T,
    config: C,
    enrichers: E,
}

/// Type-state builder for assembling a [`Runtime`].
pub struct RuntimeBuilder<S, M, L, T, C, E> {
    store: S,
    meta: M,
    limiter: L,
    telemetry: T,
    config: C,
    enrichers: E,
}

impl RuntimeBuilder<Missing, Missing, AllowAll, NullTelemetry, Missing, ()> {
    pub fn new() -> Self {
        Self {
            store: Missing,
            meta: Missing,
            limiter: AllowAll,
            telemetry: NullTelemetry,
            config: Missing,
            enrichers: (),
        }
    }
}

impl Default for RuntimeBuilder<Missing, Missing, AllowAll, NullTelemetry, Missing, ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime<Missing, Missing, AllowAll, NullTelemetry, Missing, ()> {
    pub fn builder() -> RuntimeBuilder<Missing, Missing, AllowAll, NullTelemetry, Missing, ()> {
        RuntimeBuilder::new()
    }
}

impl<M, L, T, C, E> RuntimeBuilder<Missing, M, L, T, C, E> {
    pub fn with_store<S>(self, store: S) -> RuntimeBuilder<S, M, L, T, C, E>
    where
        S: Store,
    {
        RuntimeBuilder {
            store,
            meta: self.meta,
            limiter: self.limiter,
            telemetry: self.telemetry,
            config: self.config,
            enrichers: self.enrichers,
        }
    }
}

impl<S, L, T, C, E> RuntimeBuilder<S, Missing, L, T, C, E> {
    pub fn with_meta<M>(self, meta: M) -> RuntimeBuilder<S, M, L, T, C, E>
    where
        M: MetaExtractor,
    {
        RuntimeBuilder {
            store: self.store,
            meta,
            limiter: self.limiter,
            telemetry: self.telemetry,
            config: self.config,
            enrichers: self.enrichers,
        }
    }
}

impl<S, M, L, T, E> RuntimeBuilder<S, M, L, T, Missing, E> {
    pub fn with_config<C>(self, config: C) -> RuntimeBuilder<S, M, L, T, C, E>
    where
        C: ConfigSource,
    {
        RuntimeBuilder {
            store: self.store,
            meta: self.meta,
            limiter: self.limiter,
            telemetry: self.telemetry,
            config,
            enrichers: self.enrichers,
        }
    }
}

impl<S, M, L, T, C, E> RuntimeBuilder<S, M, L, T, C, E> {
    pub fn with_limiter<L2>(self, limiter: L2) -> RuntimeBuilder<S, M, L2, T, C, E>
    where
        L2: Limiter,
    {
        RuntimeBuilder {
            store: self.store,
            meta: self.meta,
            limiter,
            telemetry: self.telemetry,
            config: self.config,
            enrichers: self.enrichers,
        }
    }

    pub fn with_telemetry<T2>(self, telemetry: T2) -> RuntimeBuilder<S, M, L, T2, C, E>
    where
        T2: Telemetry,
    {
        RuntimeBuilder {
            store: self.store,
            meta: self.meta,
            limiter: self.limiter,
            telemetry,
            config: self.config,
            enrichers: self.enrichers,
        }
    }

    pub fn with_enrichers<E2>(self, enrichers: E2) -> RuntimeBuilder<S, M, L, T, C, E2>
    where
        E2: EnricherChain,
    {
        RuntimeBuilder {
            store: self.store,
            meta: self.meta,
            limiter: self.limiter,
            telemetry: self.telemetry,
            config: self.config,
            enrichers,
        }
    }
}

impl<S, M, L, T, C, E> RuntimeBuilder<S, M, L, T, C, E>
where
    S: Store,
    M: MetaExtractor,
    L: Limiter,
    T: Telemetry,
    C: ConfigSource,
    E: EnricherChain,
{
    pub fn build(self) -> Result<Runtime<S, M, L, T, C, E>> {
        Ok(Runtime {
            store: self.store,
            meta: self.meta,
            limiter: self.limiter,
            telemetry: self.telemetry,
            config: self.config,
            enrichers: self.enrichers,
        })
    }
}

impl<S, M, L, T, C, E> Runtime<S, M, L, T, C, E>
where
    S: Store,
    M: MetaExtractor,
    L: Limiter,
    T: Telemetry,
    C: ConfigSource,
    E: EnricherChain,
{
    pub async fn handle(
        &self,
        request: HandleRequest,
        reader: &mut (dyn AsyncRead + Send + Unpin),
    ) -> Result<()> {
        self.telemetry.emit(TelemetryEvent {
            name: "handle_start".to_string(),
        });
        let mut timer = StageTimer::default();

        timer.start("load_config");
        let config_root = self.config.load().await?;
        timer.end("load_config");

        timer.start("collect_metadata");
        let mut metadata = self.meta.extract(&request).await?;
        timer.end("collect_metadata");

        timer.start("resolve_config");
        let config = self
            .config
            .resolve(&config_root, &metadata)
            .await
            .context("resolve config overrides")?;
        metadata.symbolization_mode = Some(symbolizer_mode_name(&config.symbolizer).to_string());
        timer.end("resolve_config");

        let mut decision = if config.respect_dumpable && metadata.dumpable != Some(true) {
            Decision {
                allowed: false,
                reason: "dumpable_not_allowed".to_string(),
                key: "dumpable".to_string(),
            }
        } else {
            timer.start("rate_limit");
            let decision = evaluate_decision(&self.limiter, &config, &metadata).await;
            timer.end("rate_limit");
            decision
        };

        let mut core_result = None;
        let mut dump = DumpRecord {
            stored: false,
            reason: if decision.key == "dumpable" {
                "dumpable_not_allowed".to_string()
            } else {
                "not_attempted".to_string()
            },
        };

        if decision.allowed {
            timer.start("store_core");
            let core_opts = CoreWriteOptions {
                output_dir: config.output_dir.clone(),
                file_name: build_core_filename(
                    request.kernel.pid,
                    request.kernel.signal,
                    config.core.compression,
                ),
                compression: config.core.compression,
                sparse: config.core.sparse,
                min_free_percent: config.core.min_free_percent,
            };

            match self.store.write_core(reader, &core_opts).await {
                Ok(result) => {
                    core_result = Some(result);
                    dump.stored = true;
                    dump.reason = "stored".to_string();
                }
                Err(err) if is_storage_reserve_refusal(&err) => {
                    decision = Decision {
                        allowed: false,
                        reason: format!("storage_refused:{err}"),
                        key: "storage".to_string(),
                    };
                    dump.reason = "storage_refused".to_string();
                }
                Err(err) => {
                    return Err(err).context("write core stream");
                }
            }
            timer.end("store_core");
        } else if dump.reason == "not_attempted" {
            dump.reason = decision.key.clone();
        }

        timer.start("enrich_record");
        let mut record = CrashRecord {
            schema_version: 3,
            metadata,
            stack: None,
            core: core_result,
            rate_limit: decision,
            dump,
            telemetry: TelemetryRecord::default(),
        };
        let enrichment = EnrichmentContext {
            config: &config,
            request: &request.kernel,
        };
        self.enrichers.run(&enrichment, &mut record).await?;
        timer.end("enrich_record");

        timer.start("store_record");
        record.telemetry = TelemetryRecord {
            stage_ms: timer.snapshot(),
        };
        self.store.write_record(&config, &record).await?;
        timer.end("store_record");
        self.telemetry.emit(TelemetryEvent {
            name: "handle_complete".to_string(),
        });

        Ok(())
    }
}

fn symbolizer_mode_name(config: &EffectiveSymbolizerConfig) -> &'static str {
    match config {
        EffectiveSymbolizerConfig::None => "none",
        EffectiveSymbolizerConfig::Local => "local",
        EffectiveSymbolizerConfig::Debuginfod => "debuginfod",
        EffectiveSymbolizerConfig::Http(_) => "http",
    }
}

async fn evaluate_decision<L>(
    limiter: &L,
    config: &EffectiveConfig,
    metadata: &crate::meta::CrashMetadata,
) -> Decision
where
    L: Limiter,
{
    match limiter.check(config, metadata).await {
        Ok(decision) => decision,
        Err(err) => Decision {
            allowed: false,
            reason: format!("rate_limiter_error:{err}"),
            key: "rate_limiter".to_string(),
        },
    }
}

fn build_core_filename(pid: i32, signal: Option<i32>, compression: Compression) -> String {
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let sig = signal.unwrap_or(0);
    let ext = match compression {
        Compression::None => "core",
        Compression::Zstd => "core.zst",
        Compression::Xz => "core.xz",
    };
    format!("{ts}-pid{pid}-sig{sig}.{ext}")
}

fn is_storage_reserve_refusal(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .to_string()
            .contains("refusing to store core: filesystem")
    })
}
