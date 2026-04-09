---
title: Testing
weight: 40
---

Coregate has a QEMU-based integration harness for real crash testing inside a Debian guest.

## Fetch the Debian guest image

```bash
cargo run -p xtask -- vmtest fetch-image
```

## Build guest tools

```bash
cargo run -p xtask -- vmtest build-guest-tools
```

## Run all scenarios

```bash
cargo run -p xtask -- vmtest run --scenario all
```

## Run one scenario

```bash
cargo run -p xtask -- vmtest run --scenario core-pattern-segv
cargo run -p xtask -- vmtest run --scenario server-legacy-segv
cargo run -p xtask -- vmtest run --scenario server-segv
```

## Notes

- `server-legacy-segv` requires an external 6.16+ kernel/initrd.
- `server-segv` requires an external 6.19+ kernel/initrd.
- the harness uses a guest-side `vmtest-agent` over a virtio-serial control channel
- guest tools are built for `x86_64-unknown-linux-musl` to avoid host/guest glibc drift
