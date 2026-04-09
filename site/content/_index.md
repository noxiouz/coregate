---
title: coregate
summary: Linux coredump collection in Rust.
---

Coregate collects Linux coredumps in two kernel-facing modes:

- `handle`: `core_pattern` pipe helper mode
- `serve` / `serve-legacy`: socket modes for newer kernels

It focuses on the fast path first: drain the dump, extract useful metadata, store the core, and get out of the kernel's way.
