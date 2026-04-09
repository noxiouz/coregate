---
title: Quickstart
weight: 10
summary: Build Coregate, configure kernel delivery, and optionally enable the BPF stack tracer.
---

## Build

```bash
cargo build -p coregate
cargo build -p coregate-bpf
```

## Configure `core_pattern` handle mode

Dry run:

```bash
cargo run -p coregate -- setup handle
```

Apply:

```bash
sudo cargo run -p coregate -- setup handle --apply
```

This installs the canonical kernel invocation:

```text
|/path/to/coregate handle %P %i %I %s %t %d %E /etc/coregate/config.json
```

## Configure socket modes

Legacy socket mode (`@`, Linux 6.16+):

```bash
cargo run -p coregate -- setup server-legacy
sudo cargo run -p coregate -- setup server-legacy --apply
```

Protocol socket mode (`@@`, Linux 6.19+):

```bash
cargo run -p coregate -- setup server
sudo cargo run -p coregate -- serve --apply-sysctl
```

`coregate setup` checks the running kernel version and rejects unsupported socket modes. For protocol socket mode, `serve --apply-sysctl` is the long-running server command that also installs the dynamic `@@...` pattern.

## Config

Start from the example:

```bash
cp docs/config.example.json /etc/coregate/config.json
```

## Optional: enable BPF stack capture

```bash
sudo cargo run -p coregate-bpf -- install --force
sudo cargo run -p coregate -- debug-bpf-stats --json
```

This pins the tracer under `/sys/fs/bpf/coregate` and lets `coregate` enrich crash records with raw user addresses, best-effort live symbols, and normalized file-offset metadata for later symbolization.

## Local run

```bash
coregate --help
coregate handle --help
coregate setup --help
coregate debug-bpf-stack --help
```
