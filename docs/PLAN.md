# Coregate Plan And Progress

Last updated: 2026-04-09

## Status

### Completed

- `core_pattern` collector MVP in Rust
- positional CLI arguments suitable for `core_pattern`
- local metadata extraction from `/proc` and ELF files
- local JSONL sink
- local SQLite sink behind a default-enabled feature
- local persistent rate limiting
- compressed core storage (`zstd`, `xz`) and sparse uncompressed writes
- fail-closed `PR_DUMPABLE` handling
- hot-path refactor so expensive enrichment happens after core draining
- QEMU-based Debian VM harness
- guest control plane over virtio-serial with a guest `vmtest-agent`
- musl guest binaries for VM tests to avoid host/guest glibc mismatch
- `xtask` wrapper for fetching images, building guest tools, listing scenarios, and running VM tests
- end-to-end VM scenarios:
  - `core-pattern-segv`
  - `deleted-exe`
  - `dumpable-off`

### In Progress

- building out scenario coverage in the VM harness
- shaping the VM harness so it can later be moved into a reusable repo and wrapped by Bazel

### Not Started

- socket mode ingress for kernel 6.16+
- distributed rate limiting
- GDB-based stack extraction
- BPF-based stack extraction and symbolization
- CPU register extraction from core notes or helper metadata
- ClickHouse sink
- plugin crate/runtime reintroduction once there is an actual extension surface
- Bazel VM test integration
- VM image build pipeline beyond cloud-image usage

## Goals

- Collect Linux coredumps in two modes:
  - `core_pattern` handler mode
  - socket mode (kernel >= 6.16)
- Keep the fast path optimized to minimize crash-process retention.
- Support extensible metadata extraction, stack tracing, rate limiting, storage, and telemetry.
- Keep test coverage kernel-aware so the same userspace can be exercised with kernels before and after 6.16.

## Current Architecture

### Workspace

- `collector-kernel`: ingress abstractions (`PatternPipe`, future `SocketMode`)
- `collector-meta`: metadata extraction
- `collector-core`: sparse/compressed core writer
- `collector-store`: JSON local + feature-gated SQLite/ClickHouse sinks
- `collector-limit`: local/distributed limiters
- `collector-telemetry`: stage timings
- `coregate`: executable wiring everything together
- `victim-crash`: crash fixture binary for guest tests
- `vmtest-protocol`: host/guest test protocol
- `vmtest-agent`: guest-side test driver
- `vmtest`: host-side QEMU harness and scenario library
- `xtask`: developer wrapper around the VM flow

### Collector Flow

Current `handle` CLI shape:

```text
coregate handle <pid> <tid> <tid_initial> <signal> <epoch> <dumpable> <exe> <config>
```

Current `core_pattern` example:

```text
|/usr/local/bin/coregate handle %P %i %I %s %t %d %E /etc/coregate/config.json
```

Current setup helper:

```text
coregate setup handle
coregate setup server-legacy --socket-address @/run/coregate-coredump.socket
coregate setup server --socket-address @@/run/coregate-coredump.socket
```

Current collection flow:

1. Load config.
2. Collect fast metadata from `/proc`.
3. Override dumpability from kernel-provided `%d` when available.
4. Enforce `PR_DUMPABLE` policy fail-closed when enabled.
5. Evaluate local rate limits.
6. Drain stdin and store the core.
7. Enrich metadata after the core is drained.
8. Write JSONL metadata.
9. Optionally write SQLite metadata when built with the `sqlite` feature.

## Delivered Features

### Metadata

- pid, tid, namespace pid
- thread name
- binary name and path
- build ID
- uptime
- cgroup path
- deleted-executable detection
- dumpable state
- package version via `dpkg-query` or `rpm` when enabled

### Core Storage

- uncompressed writes
- `zstd` compression
- `xz` compression
- sparse file support for uncompressed writes

### VM Test Harness

- Debian 12 `generic` qcow2 image fetch helper
- temporary cloud-init seed image
- temporary tools image carrying guest binaries and config
- qcow2 overlay creation from a base image
- QEMU boot with optional external kernel/initrd/append overrides
- guest control via virtio-serial and `vmtest-agent`
- musl guest binaries built for `x86_64-unknown-linux-musl`
- scenario-driven Rust integration tests and `xtask` wrapper

## Roadmap

### Phase 1: Solidify `core_pattern` path

Status: mostly complete

Remaining work:

- add more VM scenarios:
  - `thread-crash`
  - `rate-limited`
  - possibly package lookup scenarios on Debian/Fedora
- improve host-side progress and artifact reporting as needed
- decide whether JSON config is enough short-term or whether protobuf parsing should be added early

### Phase 2: Add richer metadata and stack extraction

Status: not started

- GDB stack provider
- CPU register extraction from core notes
- evaluate how stack/provider outputs should land in JSON and SQLite

### Phase 3: Add socket mode and kernel-version coverage

Status: not started

- socket mode ingress for kernel 6.16+
- early allow/deny decision for socket mode
- test matrix for:
  - pre-6.16 kernels with `core_pattern`
  - 6.16+ kernels with socket mode

### Phase 4: Add advanced integrations

Status: not started

- distributed rate limiting (`Redis` or `Memcache`)
- BPF stack provider plus symbolization (`blazesym` or equivalent)
- ClickHouse sink
- runtime plugin model
- Bazel wrapper around the existing VM runner

## BPF Stack Tracer Plan

Status: not started

- Hook around `do_coredump`
- Capture frame addresses into a pinned map keyed by global pid/tgid
- Collector reads frames and symbolizes them
- Fallback to GDB provider
