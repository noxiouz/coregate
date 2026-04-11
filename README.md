# coregate

`coregate` is a Rust coredump collector for Linux. The shipped binary supports
`handle`, the classic `core_pattern` pipe helper mode, plus socket server modes
for newer kernels.

The library is being shaped so downstream binaries can assemble their own
collector with custom storage, metadata, limiting, telemetry, and enrichment
modules. The standard CLI glue is reusable through `crates/coregate-cli`, so a
custom binary can keep Coregate's kernel argument contract while replacing the
module implementation chain.

The project is built around a fast crash path: drain the core, collect useful
metadata, store the dump with explicit policy, and get out of the kernel's way.

Current capabilities include:

- metadata extraction from `/proc` and ELF data
- JSONL output and optional SQLite indexing
- compressed or sparse core storage
- optional BPF-based stack capture from `do_coredump`
- local rate limiting and dumpability checks
- async socket ingress for `@` and `@@` kernel coredump modes
- QEMU-backed VM integration tests for real kernel delivery paths

Configuration JSON is parsed into protobuf-generated Rust types. The schema is
in [crates/coregate/proto/config.proto](crates/coregate/proto/config.proto).

For setup, build, VM testing, and site instructions, see
[docs/USAGE.md](docs/USAGE.md).
