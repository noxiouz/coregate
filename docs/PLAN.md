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
- first BPF stack tracer capture path:
  - `kprobe/do_coredump`
  - `bpf_get_stack(..., BPF_F_USER_STACK)`
  - pinned LRU map under `/sys/fs/bpf/coregate`
  - optional best-effort stack enrichment in `coregate`
  - `blazesym` live process symbolization plus remote-friendly normalization
  - standalone `coregate-bpf` loader
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
- validating BPF capture across kernels and preparing later symbolization

### Not Started

- socket mode ingress for kernel 6.16+
- distributed rate limiting
- GDB-based stack extraction
- BPF symbolization and richer stack/debug data
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

### BPF Stack Tracer

- separate loader binary: `coregate-bpf`
- pinned BPF objects under `/sys/fs/bpf/coregate`
- fixed stack record shape: `count + 32 user addresses`
- LRU hash map keyed by global pid/tgid
- best-effort map read in the collector fast path
- `blazesym` user-space symbolization and normalized file-offset metadata
- debug inspection commands:
  - `coregate debug-bpf-stack <pid>`
  - `coregate debug-bpf-stats`
- host validation on Linux `6.6.87.2-microsoft-standard-WSL2`:
  - `do_coredump` kprobe fired
  - `bpf_get_stack` captured 8 frames
  - `coregate` read the pinned stack entry successfully

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

Status: in progress

- GDB stack provider
- CPU register extraction from core notes
- BPF symbolization in user space
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

Status: first capture path complete

- Hook around `do_coredump`
- Capture frame addresses into a pinned map keyed by global pid/tgid
- Collector reads frames from the pinned map
- Symbolize later in user space
- Fallback to GDB provider
