# Usage

## Build

Build the shipped binary:

```bash
cargo build --bin coregate
cargo build -p coregate-bin --bin coregate
```

Build the reusable library crate only:

```bash
cargo build -p coregate
cargo build -p coregate --no-default-features
cargo build -p coregate --features bpf
```

Default `coregate` library builds include SQLite metadata support and exclude
collector-side BPF readout. Build the binary with the dependency feature when
you need BPF stack enrichment:

```bash
cargo build -p coregate-bin --bin coregate --features coregate/bpf
```

## Handle Mode

The standard CLI exposes the handle-mode collector. It expects the positional
arguments used by Linux `core_pattern` and reads the core stream from `stdin`.

```bash
coregate handle 1234 1234 1234 11 1710000000 1 /usr/bin/my-app ./docs/config.example.json < corefile.bin
```

Canonical `core_pattern` shape:

```text
|/usr/local/bin/coregate handle %P %i %I %s %t %d %E /etc/coregate/config.json
```

Render or apply the handle-mode setup:

```bash
coregate setup handle
sudo coregate setup handle --apply
```

## Server Modes

Legacy socket mode (`@`, Linux 6.16+):

```bash
coregate setup server-legacy
sudo coregate setup server-legacy --apply
coregate serve-legacy --socket-address @/run/coregate-coredump.socket
```

Protocol socket mode (`@@`, Linux 6.19+):

```bash
coregate setup server
sudo coregate setup server --apply
coregate serve --socket-address @@/run/coregate-coredump.socket
```

Both server modes are async ingress adapters. They parse the kernel socket
protocol, derive a normalized crash request, and pass the socket stream into the
same module runtime used by handle mode. They do not write sysctls; only
`coregate setup ... --apply` writes `kernel.core_pattern` or
`kernel.core_pipe_limit`.

## Library Composition

`crates/coregate` exposes a builder so downstream binaries can assemble their
own collector from default or custom modules. The runtime handler is async and
accepts a `tokio::io::AsyncRead` core stream.

```rust
let runtime = coregate::Runtime::builder()
    .with_config(FileConfigSource::new("/etc/coregate/config.json"))
    .with_meta(ProcfsMeta::new())
    .with_store(LocalStore::new())
    .with_limiter(PolicyLimiter::new())
    .with_enrichers(default_enrichers())
    .build()?;

runtime.handle(request, &mut core_stream).await?;
```

`crates/coregate-cli` provides the standard Coregate CLI contract. It keeps the
`handle` positional argument order aligned with `coregate setup`, while still
letting the binary choose the runtime modules:

```rust
fn main() {
    coregate_cli::run(build_runtime).unwrap();
}
```

A downstream binary that needs a different command-line contract can skip
`coregate-cli` and call `crates/coregate` APIs directly.

See [docs/MODULE_SYSTEM.md](MODULE_SYSTEM.md) for module traits and extension
points.

## BPF Stack Tracer

How it works:

- a separate `coregate-bpf` utility attaches `kprobe/do_coredump`
- the BPF program stores up to 32 user return addresses in a pinned LRU map keyed by global pid/tgid
- `coregate` reads and deletes that entry during crash handling when the library is built with `coregate/bpf`
- user space adds best-effort `blazesym` symbols plus normalized file offsets for later symbolization

Install the pinned tracer objects:

```bash
sudo cargo run -p coregate-bpf -- install
```

Replace existing pinned objects:

```bash
sudo cargo run -p coregate-bpf -- install --force
```

Remove the pinned tracer objects:

```bash
sudo cargo run -p coregate-bpf -- remove
```

Notes:

- BPF objects are pinned under `/sys/fs/bpf/coregate`
- the collector binary needs `--features coregate/bpf` for crash-record stack enrichment
- stack records carry best-effort live `blazesym` symbols and normalized file-offset metadata
- debuginfod-backed symbolization can be enabled with:
  - `"symbolizer": { "mode": "debuginfod" }`
- debuginfod mode uses the standard debuginfod client settings:
  - `DEBUGINFOD_URLS` for server URLs
  - `DEBUGINFOD_CACHE_PATH` for an explicit cache path
  - otherwise the platform cache directory, typically `~/.cache/debuginfod_client`
- remote HTTP symbolization can be enabled with:
  - `"symbolizer": { "mode": "http", "http": { "url": "...", "timeout_ms": 3000 } }`

Remote HTTP contract:

- request fields: `provider`, `process`, `modules[]`, `frames[]`
- response fields: `frames[]` with `symbol`, `module`, `offset`, `file`, `line`, `column`, and `reason`
- the HTTP body uses protobuf-generated message types serialized as JSON
- the shared schema lives in `crates/symbolizer-proto/proto/symbolizer.proto`

## VM Tests

```bash
cargo run -p xtask -- vmtest fetch-image
cargo run -p xtask -- vmtest build-guest-tools
cargo run -p xtask -- vmtest run --scenario all
```

Run one scenario:

```bash
cargo run -p xtask -- vmtest run --scenario core-pattern-segv
cargo run -p xtask -- vmtest run --scenario deleted-exe
```

Socket-mode scenarios require an explicit guest kernel:

```bash
COREGATE_VM_KERNEL=/path/to/bzImage \
COREGATE_VM_INITRD=/path/to/initrd.img \
cargo run -p xtask -- vmtest run --scenario server-legacy-segv

COREGATE_VM_KERNEL=/path/to/bzImage \
COREGATE_VM_INITRD=/path/to/initrd.img \
cargo run -p xtask -- vmtest run --scenario server-segv
```

Bazel can produce the 6.19 kernel/initrd pair from the Debian rootfs and run
both socket protocols without pre-populated `.cache` files:

```bash
bazel test //tests/vm:server_legacy_segv //tests/vm:server_segv --test_output=errors
```

Those targets use `vm_kernel_from_guest_packages` to boot the rootfs, install
the requested Ubuntu mainline kernel packages, run `update-initramfs`, and
export declared `vmlinuz`/`initrd` outputs for direct QEMU boot.

## Website

The Hugo site lives under `site/` and is deployed with
`.github/workflows/pages.yml`.

Local build:

```bash
.cache/tools/hugo/hugo --source site --destination ../site-public --minify
```
