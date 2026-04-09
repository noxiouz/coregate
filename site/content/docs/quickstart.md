---
title: Quickstart
weight: 10
---

## Build

```bash
cargo build -p coregate
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
sudo cargo run -p coregate -- setup server --apply
```

`coregate setup` checks the running kernel version and rejects unsupported socket modes.

## Config

Start from the example:

```bash
cp docs/config.example.json /etc/coregate/config.json
```

## Local run

```bash
coregate --help
coregate handle --help
coregate setup --help
```
