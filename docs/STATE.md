# Current State

Last updated: 2026-04-09

## Summary

The repo has a working Rust `core_pattern` collector MVP and a working QEMU-based Debian VM test harness.

Implemented and verified:

- `core_pattern` ingestion via positional CLI arguments
- local JSONL and SQLite metadata sinks
- local persistent rate limiting
- compressed and sparse core storage
- fail-closed `PR_DUMPABLE` handling
- QEMU guest testing with virtio-serial guest control
- musl guest binaries for stable cross-distro VM execution
- end-to-end VM scenarios:
  - `core-pattern-segv`
  - `deleted-exe`
  - `dumpable-off`

## Source Of Truth

Progress, architecture, and roadmap now live in:

- [docs/PLAN.md](/home/noxiouz/github/coregate/docs/PLAN.md)

Use this file as a quick snapshot only.
