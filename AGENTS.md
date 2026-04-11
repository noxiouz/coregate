# Repository Guidelines

## Project Structure & Module Organization

`coregate` is a Rust workspace. Main packages live under `crates/`:

- `bin/coregate.rs`: shipped `coregate` binary; keep it as a small consumer of the library runtime
- `crates/coregate-cli`: reusable standard CLI front-end; it owns the `handle` positional argument contract used by `setup`
- `crates/coregate`: reusable collector library; key modules are `modules`, `runtime`, `defaults`, `setup`, `ingress`, `dump`, `store`, and `bpf`
- `crates/bpf-stack`, `crates/bpf-loader`: optional BPF stack tracing support
- `crates/symbolizer-proto`: shared protobuf schema for symbolization APIs
- `crates/vmtest`: QEMU harness, guest protocol, and guest fixture binaries
- `crates/vmtest-scenarios`: scenario catalog and VM integration tests
- `crates/xtask`: developer wrapper around VM test flows

Docs and examples live in `docs/`. The GitHub Pages site is under `site/`. Bazel rules are in `BUILD.bazel`, `MODULE.bazel`, and `bzl/`. VM smoke tests also exist under `tests/vm/`.

## Build, Test, and Development Commands

- `cargo build --bin coregate`: build the shipped binary
- `cargo build -p coregate`: build the reusable library crate
- `cargo test -p coregate`: run unit tests for the library crate
- `cargo test --workspace`: run the Rust test suite
- `cargo clippy -p coregate -p coregate-cli -p coregate-bin -p vmtest -p vmtest-scenarios -p xtask --all-targets`: lint the main collector and VM tooling
- `cargo run -p xtask -- vmtest fetch-image`: fetch the Debian guest image
- `cargo run -p xtask -- vmtest build-guest-tools`: build guest binaries for VM tests
- `cargo run -p xtask -- vmtest run --scenario all`: run QEMU-backed integration scenarios
- `bazel test //...`: run default Bazel tests; QEMU VM scenarios are `manual`
- `bazel test //tests/vm:vm_tests`: run the explicit QEMU VM test suite
- `.cache/tools/hugo/hugo --source site --destination ../site-public --minify`: build the docs site locally

## Coding Style & Naming Conventions

Use standard Rust formatting and keep code ASCII unless a file already requires Unicode. Run `cargo fmt` and `cargo clippy --workspace --all-targets` before submitting Rust changes. Prefer small, focused crates and explicit names: `serve-legacy`, `server-segv`, `thread-crash`. Keep kernel-facing behavior concrete and avoid hidden magic in setup paths.

## Testing Guidelines

Unit tests live next to Rust code. Scenario-based VM tests live in `crates/vmtest-scenarios/tests/scenarios/` and use descriptive snake_case names such as `dumpable_off.rs` and `server_legacy_segv.rs`. For kernel-mode changes, add or update a VM scenario instead of relying only on unit tests.

## Important Context For Agents

- `bin/coregate.rs` should stay minimal. Treat it as a third-party-style consumer that passes a runtime builder into `coregate_cli::run`.
- `crates/coregate-cli` owns the standard CLI contract. Put command parsing there when it must stay aligned with `coregate setup`; do not let the root binary grow private parsing logic again.
- The current shipped binary exposes `handle`, `serve`, `serve-legacy`, and `setup`. `setup` is synchronous and should not require starting Tokio.
- Module traits are async-capable through `BoxResultFuture<'a, T>`. Prefer that explicit boxed future style unless the project intentionally adopts `async-trait`.
- `coregate setup` logic in `setup` is the source of truth for kernel integration strings. Do not hand-edit example `core_pattern` strings without keeping setup rendering aligned.
- Kernel modes are versioned:
  - `handle`: classic pipe helper, no kernel version gate
  - `server-legacy`: `@/path.sock`, requires Linux `>= 6.16`
  - `server`: `@@/path.sock`, requires Linux `>= 6.19`
- `@` and `@@` are different kernel protocols, not cosmetic aliases. Treat them as separate ingress implementations.
- The hot path matters. Avoid adding expensive metadata enrichment before the core stream is drained.
- Keep `crates/coregate/src/lib.rs` as module wiring and public re-exports only. Put third-party-style binary parsing in `bin/coregate.rs`, setup rendering in `setup`, socket protocols in `ingress`, and reusable collection flow in `runtime`.
- `coregate` defaults to SQLite enabled and BPF disabled. Use `--no-default-features` on the library to drop SQLite, `--features bpf` on the library for BPF readout tests, and `--features coregate/bpf` when building the root binary.
- Keep feature gates scoped by module where possible. SQLite cfgs belong in `coregate::store`; BPF cfgs belong in `coregate::bpf`.
- `libbpf-sys` should not enter the default `coregate` dependency graph. Keep it isolated to `coregate-bpf-stack`/`coregate-bpf` or the `coregate` `bpf` feature.
- VM tests are the main safety net for kernel-facing behavior. Prefer extending `crates/vmtest-scenarios/tests/scenarios/` over adding only mock/unit coverage.
- Bazel VM rules transition guest-side `test`, `data`, and `vmtest-agent` labels to `//:linux_x86_64_musl`. Keep the host-side `vmtest` runner in exec config.
- Guest tools for VM tests are built for `x86_64-unknown-linux-musl` to avoid host/guest glibc mismatch. Do not casually switch that path back to glibc.
- Bazel VM tests are tagged `manual`; `bazel test //tests/vm/...` skips them. Use explicit labels or `bazel test //tests/vm:vm_tests`.
- Bazel VM tests use `//tests/vm:coregate_guest`, which wraps the no-SQLite `//:coregate_guest` musl build. Keep guest configs with `metadata_sqlite` disabled unless a musl-compatible SQLite C toolchain is wired.
- Bazel socket-mode VM tests use `//tests/vm:linux_6_19_kernel`, generated by `vm_kernel_from_guest_packages`. Do not replace it with committed or `.cache/` kernel files; the rule boots the Debian rootfs, installs kernel packages, and exports declared kernel/initrd outputs.
- Bazel BPF stack support is opt-in and tagged `manual`; do not put `libbpf-sys` back on the default `bazel build //...` path.
- `vm_python_test` is source-only for now. It runs the copied Python file with guest `/usr/bin/python3`; do not add Bazel Python `deps` until runfiles copying is implemented.
- The site in `site/` is plain Hugo with custom layouts, no external theme. Keep it self-contained.

## Security & Configuration Tips

Do not commit generated VM images, kernels, `target/`, `site-public/`, or local caches. Use setup dry runs before `--apply`, especially for `server-legacy` and `server`, which are kernel-version gated.
