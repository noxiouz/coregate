# Coregate Module System

Coregate is split into a reusable library crate and a small binary that
assembles concrete modules. The shipped binary lives at `bin/coregate.rs` on
purpose: treat it like a downstream consumer of `crates/coregate`, not as the
owner of the collector logic.

The standard command-line contract lives in `crates/coregate-cli`. The root
binary passes one callable into `coregate_cli::run`; that callable receives the
selected config path and returns a built `Runtime`.

Status: `handle`, `serve-legacy`, and `serve` all feed the builder-backed
runtime. `setup` is exposed by the root binary as a synchronous command because
it only renders or writes kernel sysctls.

## Goals

- Let third-party binaries reuse the collector runtime without forking it.
- Keep required extension points explicit and compile-time checked.
- Keep the crash hot path simple: drain the core first, enrich later.
- Keep module selection static by default, with no per-event vtable dispatch.
- Let storage, limiters, config sources, and symbolization/enrichment await I/O
  without changing the ingress API again.

## Public Surface

The extension traits live in `crates/coregate/src/modules.rs`:

| Module | Required | Default | Purpose |
| --- | --- | --- | --- |
| `ConfigSource` | yes | none | Load config and resolve overrides for a crash. |
| `MetaExtractor` | yes | none | Build initial metadata from kernel/procfs state. |
| `Store` | yes | none | Store the core stream and crash record. |
| `Limiter` | no | `AllowAll` | Decide whether the core stream may be stored. |
| `Telemetry` | no | `NullTelemetry` | Emit runtime events. |
| `EnricherChain` | no | `()` | Run post-storage record enrichment. |

Trait methods return `BoxResultFuture<'a, T>`. That is the explicit form of
what the `async-trait` crate would generate for `async fn` methods. It keeps
the extension API async-capable without adding a macro dependency.

Built-in implementations live in `crates/coregate/src/defaults.rs`:

| Type | Trait | Notes |
| --- | --- | --- |
| `FileConfigSource` | `ConfigSource` | Loads JSON config and protobuf-backed schema. |
| `ProcfsMeta` | `MetaExtractor` | Reads process metadata from `/proc`. |
| `LocalStore` | `Store` | Writes core artifacts, JSONL metadata, and optional SQLite rows. |
| `PolicyLimiter` | `Limiter` | Uses the configured local rate-limit state file. |
| `AllowAll` | `Limiter` | No-op default. |
| `NullTelemetry` | `Telemetry` | No-op default. |
| `BinaryMetadataEnricher` | `Enricher` | Adds ELF/package metadata after core drain. |
| `BpfStackEnricher` | `Enricher` | Adds optional BPF stack data. |

## Runtime Builder

`RuntimeBuilder` uses a type-state marker named `Missing`. Required slots start
as `Missing`; optional slots start with no-op defaults. `build()` is only
available once `ConfigSource`, `MetaExtractor`, and `Store` have been provided.

```rust
let runtime = coregate::Runtime::builder()
    .with_config(FileConfigSource::new("/etc/coregate/config.json"))
    .with_meta(ProcfsMeta::new())
    .with_store(LocalStore::new())
    .with_limiter(PolicyLimiter::new())
    .with_enrichers(default_enrichers())
    .build()?;
```

A downstream binary can replace a single module and keep the rest:

```rust
let runtime = coregate::Runtime::builder()
    .with_config(FileConfigSource::new(config_path))
    .with_meta(ProcfsMeta::new())
    .with_store(MyObjectStore::new(bucket))
    .with_limiter(PolicyLimiter::new())
    .build()?;
```

To reuse the standard CLI while replacing modules:

```rust
fn main() {
    coregate_cli::run(build_runtime).unwrap();
}

fn build_runtime(config_path: PathBuf) -> Result<MyRuntime> {
    coregate::Runtime::builder()
        .with_config(FileConfigSource::new(config_path))
        .with_meta(ProcfsMeta::new())
        .with_store(MyObjectStore::new())
        .build()
}
```

If the standard CLI is too restrictive, a downstream binary can ignore
`coregate-cli` and call `crates/coregate` runtime/ingress APIs directly.

## Handle Mode Flow

The implemented runtime entry point is async:

```rust
runtime.handle(request, &mut core_stream).await?;
```

The standard `coregate-cli` front-end parses kernel positional arguments,
constructs a `HandleRequest`, and passes `tokio::io::stdin()` as the core
stream.

Flow:

1. Load config.
2. Extract initial metadata.
3. Resolve config overrides.
4. Enforce dumpable policy before consuming rate-limit budget.
5. Evaluate limiter policy.
6. Drain and store the core stream when admitted.
7. Build the crash record.
8. Run enrichers after the core stream is drained.
9. Store the metadata record.

## Ingress Boundary

Kernel ingress modes are not module traits. They are kernel wire protocols that
should feed normalized requests into the runtime.

| Mode | Status | Pattern |
| --- | --- | --- |
| `handle` | implemented in the new runtime | `|... coregate handle ...` |
| `serve-legacy` | implemented async adapter | `@/path.sock` |
| `serve` | implemented async adapter | `@@/path.sock` |

## Notes

- Add new hot-path behavior behind a trait only when a downstream binary could
  reasonably replace it.
- Keep expensive enrichment out of metadata extraction. It belongs in an
  `Enricher` so it runs after core storage.
- The default `LocalStore` accepts `tokio::io::AsyncRead`. Uncompressed writes
  use async file I/O; compressed writes still use sync compression encoders
  while reading input asynchronously.
- Prefer small built-in modules over one large default implementation.
- If a module needs expensive setup, construct it before calling `build()`.
