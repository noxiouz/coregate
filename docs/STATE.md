# Current State

Last updated: 2026-04-11

## Summary

The repo has a working Rust `core_pattern` collector MVP and a working
QEMU-based Debian VM test harness. The collector is being refactored into a
reusable `coregate` library plus a root `bin/coregate.rs` binary that assembles
the default runtime through `RuntimeBuilder` and passes it into `coregate-cli`.

Implemented and verified:

- `core_pattern` ingestion via positional CLI arguments
- handle-mode runtime composition through module traits and a type-state builder
- reusable `coregate-cli` front-end that preserves the standard kernel argument contract
- async socket ingress commands: `serve` and `serve-legacy`
- local JSONL and SQLite metadata sinks
- local persistent rate limiting
- compressed and sparse core storage
- fail-closed `PR_DUMPABLE` handling
- QEMU guest testing with virtio-serial guest control
- musl guest binaries for stable cross-distro VM execution
- Bazel VM test wrapper for source-only Python scenarios
- Bazel musl guest toolchain transition for guest-side binaries
- end-to-end VM scenarios:
  - `core-pattern-segv`
  - `deleted-exe`
  - `dumpable-off`
  - `storage_refused` via Bazel `//tests/vm:storage_refused`

## Source Of Truth

Progress, architecture, and roadmap now live in:

- [docs/PLAN.md](/home/noxiouz/github/coroner/docs/PLAN.md)

Use this file as a quick snapshot only.
