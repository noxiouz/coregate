# coregate

`coregate` is a Rust coredump collector for Linux.

It supports three kernel-facing ingress modes:

- `handle`: classic `core_pattern` pipe helper mode
- `serve-legacy`: legacy socket mode using `@/path.sock`
- `serve`: protocol socket mode using `@@/path.sock`

The project is built around a fast crash path: drain the core, collect useful
metadata, store the dump with explicit policy, and get out of the kernel's way.

Current capabilities include:

- metadata extraction from `/proc` and ELF data
- JSONL output and optional SQLite indexing
- compressed or sparse core storage
- optional BPF-based stack capture from `do_coredump`
- local rate limiting and dumpability checks
- QEMU-backed VM integration tests for real kernel delivery paths

Configuration JSON is parsed into protobuf-generated Rust types. The schema is
in [crates/cli/proto/config.proto](/home/noxiouz/github/coroner/crates/cli/proto/config.proto).

For setup, build, VM testing, and site instructions, see
[docs/USAGE.md](/home/noxiouz/github/coroner/docs/USAGE.md).
