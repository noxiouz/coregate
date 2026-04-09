---
title: BPF Stack Capture
weight: 35
summary: Enable the `do_coredump` tracer, inspect pinned state, and understand what gets stored.
---

Coregate can enrich crash records with BPF-captured user stacks.

How it works:

1. `coregate-bpf` attaches a `kprobe` to `do_coredump`
2. the BPF program stores up to 32 raw user-space return addresses in a pinned LRU map keyed by global pid/tgid
3. `coregate` reads and deletes that entry during crash handling
4. user space adds best-effort `blazesym` symbols plus normalized file offsets for later remote symbolization

Current implementation:

- attaches `kprobe/do_coredump`
- captures up to 32 user-space return addresses with `bpf_get_stack(..., BPF_F_USER_STACK)`
- stores entries in a pinned LRU hash map under `/sys/fs/bpf/coregate`
- reads the entry back in `coregate`
- adds best-effort live `blazesym` symbols plus normalized file-offset metadata for later remote symbolization

## Install the tracer

```bash
sudo cargo run -p coregate-bpf -- install --force
```

## Inspect tracer state

```bash
sudo cargo run -p coregate -- debug-bpf-stats --json
sudo cargo run -p coregate -- debug-bpf-stack <pid> --json
```

## Remove the tracer

```bash
sudo cargo run -p coregate-bpf -- remove
```

## Notes

- live symbolization requires the crashing process to still be present in `/proc`
- normalized file-offset metadata is intended for later file-based or remote symbolization
- if symbolization fails, Coregate still keeps the raw frame addresses
