# Coregate Plan And Progress

Last updated: 2026-04-11

## Status

### Completed

- `core_pattern` collector MVP in Rust
- positional CLI arguments suitable for kernel `core_pattern`
- reusable `coregate` library runtime with a type-state `RuntimeBuilder`
- reusable `coregate-cli` crate that owns the standard CLI/kernel argument contract
- root `bin/coregate.rs` binary that only supplies the default runtime builder
- async-capable module trait surface for storage, config, limiter, and enrichment
- async `serve` and `serve-legacy` socket ingress adapters wired into the root binary
- local metadata extraction from `/proc` and ELF data
- local JSONL sink and default-enabled SQLite sink
- compressed core storage (`zstd`, `xz`) and sparse uncompressed writes
- minimum-free-space protection for core storage
- fail-closed `PR_DUMPABLE` handling
- local persistent rate limiting
- hot-path refactor so expensive enrichment happens after core draining
- BPF stack tracer capture path:
  - `kprobe/do_coredump`
  - `bpf_get_stack(..., BPF_F_USER_STACK)`
  - pinned LRU map under `/sys/fs/bpf/coregate`
  - standalone `coregate-bpf` loader
  - optional `coregate` readout behind the `bpf` feature
  - `blazesym` live symbolization, debuginfod support, and remote-friendly normalization
- QEMU-based Debian VM harness with virtio-serial guest control
- musl guest binaries for VM tests to avoid host/guest glibc mismatch
- scenario-driven Rust integration tests in `vmtest-scenarios`
- `xtask` wrapper for fetching images, building guest tools, listing scenarios, and running VM tests
- Bazel build targets for the main binary, BPF crates, VM harness, and VM scenario tests

### In Progress

- expanding VM scenario coverage for edge cases and newer kernel protocols
- expanding VM scenario coverage for edge cases and newer kernel protocols
- keeping the VM harness isolated enough to move into a reusable repo later
- validating BPF capture and symbolization behavior across kernel versions

### Not Started

- distributed rate limiting
- CPU register extraction from core notes or helper metadata
- ClickHouse sink
- plugin crate/runtime reintroduction once there is an actual extension surface
- VM image build pipeline beyond cloud-image usage

## Goals

- Collect Linux coredumps in classic pipe-helper mode and socket modes.
- Keep the fast path optimized to minimize crash-process retention.
- Support extensible metadata extraction, stack tracing, rate limiting, storage, and telemetry.
- Keep test coverage kernel-aware so the same userspace can be exercised with different kernels.

## Current Architecture

### Workspace

- root package `coregate-bin`: shipped `bin/coregate.rs` binary. It composes
  the library runtime like a downstream consumer would.
- `crates/coregate-cli`: reusable CLI front-end. It owns command parsing,
  `handle` positional argument order, setup dispatch, and async server command
  dispatch. Binaries pass in a runtime builder callable.
- `crates/coregate`: reusable collector library. Collector internals are Rust modules under `src/`:
  - `modules`: public extension traits
  - `runtime`: type-state builder and handle-mode runtime
  - `defaults`: built-in module implementations
  - `setup`: `core_pattern` rendering and kernel-version checks
  - `ingress`: `serve`/`serve-legacy` socket protocols
  - `dump`: compatibility shim for older internal callers
  - `kernel`: kernel request types
  - `meta`: metadata extraction
  - `corefile`: sparse/compressed core writer
  - `store`: JSONL sink and feature-gated SQLite sink
  - `limit`: local limiters
  - `telemetry`: stage timings
  - `bpf`: feature-scoped BPF stack readout and symbolization
- `crates/bpf-loader`: `coregate-bpf` loader for pinned BPF objects
- `crates/bpf-stack`: BPF map/object helpers and stack record shape
- `crates/symbolizer-proto`: shared protobuf schema for symbolizer requests
- `crates/vmtest`: reusable QEMU harness, host/guest protocol, guest agent, and crash fixture binaries
- `crates/vmtest-scenarios`: named Coregate VM scenarios and integration tests
- `crates/xtask`: developer wrapper around the VM flow

### Feature Boundaries

- `coregate` default features enable SQLite metadata.
- Build without SQLite with `cargo build -p coregate --no-default-features`.
- BPF readout is opt-in with `cargo build -p coregate --features bpf`.
- `libbpf-sys` is not linked by the default `coregate` build; it is isolated in the BPF crates.
- SQLite cfgs are scoped inside `store`, so call sites use one sink helper instead of repeated feature gates.
- BPF cfgs are scoped inside `bpf`, so call sites do not depend on `libbpf` types unless the feature is enabled.

## Collector Flow

Current root binary CLI shape:

```text
coregate handle <pid> <tid> <tid_initial> <signal> <epoch> <dumpable> <exe> <config>
coregate setup handle
coregate setup server
coregate setup server-legacy
coregate serve --socket-address @@/run/coregate-coredump.socket
coregate serve-legacy --socket-address @/run/coregate-coredump.socket
```

Canonical `core_pattern` example:

```text
|/usr/local/bin/coregate handle %P %i %I %s %t %d %E /etc/coregate/config.json
```

Setup is synchronous because it only renders or writes sysctls. Socket modes are
async ingress adapters: `serve-legacy` uses `@/path.sock` on Linux `>= 6.16`;
`serve` uses `@@/path.sock` on Linux `>= 6.19`.

Current collection flow:

1. Load config.
2. Collect fast metadata from `/proc`.
3. Override dumpability from kernel-provided `%d` when available.
4. Enforce `PR_DUMPABLE` policy fail-closed when enabled.
5. Evaluate local rate limits.
6. Drain stdin and store the core.
7. Enrich metadata after the core is drained.
8. Optionally read BPF stack data when built with the `bpf` feature.
9. Write JSONL metadata.
10. Optionally write SQLite metadata when built with the `sqlite` feature.

The runtime handle entry point is async and consumes a `tokio::io::AsyncRead`
core stream. Built-in modules return boxed futures so custom stores, remote
limiters, config sources, and symbolizers can perform real async I/O.

## VM Test Harness

- Debian 12 `generic` qcow2 image fetch helper
- temporary cloud-init seed image
- temporary tools image carrying guest binaries and config
- qcow2 overlay creation from a base image
- QEMU boot with optional external kernel/initrd/append overrides
- guest control via virtio-serial and `vmtest-agent`
- guest binaries built for `x86_64-unknown-linux-musl`
- named scenarios in `crates/vmtest-scenarios/tests/scenarios/`
- Bazel VM macros under `bzl/vm_test.bzl`
- Bazel VM macros transition guest-side `test`, `data`, and `vmtest-agent`
  targets to `//:linux_x86_64_musl`; the host-side VM runner stays in exec
  config
- Bazel Python VM tests are source-only and run via guest `/usr/bin/python3`
- Bazel handle-mode VM tests use a no-SQLite `coregate_guest` build until a
  musl C toolchain is wired for bundled SQLite

## Roadmap

### Phase 1: Strengthen Kernel Coverage

Status: in progress

- add more VM scenarios for edge cases such as rate limiting and package lookup
- expand socket-mode scenario coverage against 6.16+ and 6.19+ kernels
- improve artifact reporting from failed VM runs

### Phase 2: Add Richer Crash Metadata

Status: in progress

- CPU register extraction from core notes or helper metadata
- container identity heuristics when cgroup data is available
- package lookup scenarios on Debian and RPM-based images

### Phase 3: Add Advanced Integrations

Status: not started

- distributed rate limiting (`Redis` or `Memcache`)
- ClickHouse sink
- runtime plugin model after the extension surface is clear
- repeatable VM image build pipeline

## Debuginfod Symbolization

- Coregate uses debuginfod as the artifact distribution/indexing layer.
- Coregate-specific value stays in BPF stack capture, process/module normalization, crash-record integration, and optional batch frame symbolization.
- Symbolization flow:
  - normalize BPF frame addresses to file offsets
  - map each frame to a module build-id
  - fetch debuginfo via `GET /buildid/<build-id>/debuginfo`
  - cache the downloaded debuginfo locally
  - symbolize with `blazesym` over the downloaded artifact
- Server discovery uses `DEBUGINFOD_URLS` as the debuginfod server list.
