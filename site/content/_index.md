---
title: coregate
summary: Rust coredump collection for Linux with pipe and socket ingress, policy-aware storage, and optional BPF stack capture.
---

Coregate collects Linux coredumps in two kernel-facing modes:

- `handle`: `core_pattern` pipe helper mode
- `serve` / `serve-legacy`: socket modes for newer kernels

It focuses on the fast path first: drain the dump, extract useful metadata, store the core, optionally enrich it with BPF-captured user stacks, and get out of the kernel's way.
