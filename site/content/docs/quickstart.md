---
title: Quickstart
weight: 10
summary: Build Coregate, run handle mode, and optionally enable the BPF stack tracer.
---

## Build

```bash
cargo build --bin coregate
cargo build -p coregate-bin --bin coregate --features coregate/bpf
cargo build -p coregate-bpf
```

`coregate` is assembled from the root `bin/coregate.rs` binary. The reusable
collector implementation lives in `crates/coregate`; the standard CLI contract
lives in `crates/coregate-cli`.

## Configure `core_pattern` Handle Mode

The current shipped binary exposes handle mode:

```text
|/usr/local/bin/coregate handle %P %i %I %s %t %d %E /etc/coregate/config.json
```

That pattern keeps arguments positional so it fits the kernel `core_pattern`
length limit.

## Config

Start from the example:

```bash
cp docs/config.example.json /etc/coregate/config.json
```

## Optional: Enable BPF Stack Capture

```bash
sudo cargo run -p coregate-bpf -- install --force
cargo build -p coregate-bin --bin coregate --features coregate/bpf
```

This pins the tracer under `/sys/fs/bpf/coregate` and uses a `coregate` build
with the `coregate/bpf` dependency feature to enrich crash records with raw user
addresses, best-effort live symbols, and normalized file-offset metadata for
later symbolization.

## Local Run

```bash
coregate --help
coregate handle --help
coregate setup --help
```

Socket server modes are available from the same binary:

```bash
coregate serve-legacy --socket-address @/run/coregate-coredump.socket
coregate serve --socket-address @@/run/coregate-coredump.socket
```

Setup is also available and runs without starting the async server path:

```bash
coregate setup handle
coregate setup server-legacy
coregate setup server
```
