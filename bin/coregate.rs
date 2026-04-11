use anyhow::Result;
use coregate::Runtime;
use coregate::defaults::{
    BinaryMetadataEnricher, BpfStackEnricher, FileConfigSource, LocalStore, NullTelemetry,
    PolicyLimiter, ProcfsMeta, default_enrichers,
};
use std::path::PathBuf;

type DefaultRuntime = Runtime<
    LocalStore,
    ProcfsMeta,
    PolicyLimiter,
    NullTelemetry,
    FileConfigSource,
    (BinaryMetadataEnricher, (BpfStackEnricher, ())),
>;

fn main() {
    if let Err(err) = coregate_cli::run(build_default_runtime) {
        eprintln!("coregate error: {err:#}");
        std::process::exit(1);
    }
}

fn build_default_runtime(config: PathBuf) -> Result<DefaultRuntime> {
    Runtime::builder()
        .with_config(FileConfigSource::new(config))
        .with_meta(ProcfsMeta::new())
        .with_store(LocalStore::new())
        .with_limiter(PolicyLimiter::new())
        .with_enrichers(default_enrichers())
        .build()
}
