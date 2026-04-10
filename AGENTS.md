# Repository Guidelines

## Project Structure & Module Organization

`coregate` is a Rust workspace. Core crates live under `crates/`:

- `crates/cli`: main `coregate` binary
- `crates/meta`, `corefile`, `store`, `limit`, `kernel`, `telemetry`: collector internals
- `crates/vmtest`, `vmtest-agent`, `vmtest-protocol`, `victim-crash`, `xtask`: VM-backed integration test tooling

Docs and examples live in `docs/`. The GitHub Pages site is under `site/`. Bazel rules are in `BUILD.bazel`, `MODULE.bazel`, and `bzl/`. VM smoke tests also exist under `tests/vm/`.

## Build, Test, and Development Commands

- `cargo build -p coregate`: build the main binary
- `cargo test -p coregate`: run unit tests for the CLI crate
- `cargo test --workspace`: run the Rust test suite
- `cargo run -p xtask -- vmtest fetch-image`: fetch the Debian guest image
- `cargo run -p xtask -- vmtest build-guest-tools`: build guest binaries for VM tests
- `cargo run -p xtask -- vmtest run --scenario all`: run QEMU-backed integration scenarios
- `bazel test //...`: run Bazel targets
- `.cache/tools/hugo/hugo --source site --destination ../site-public --minify`: build the docs site locally

## Coding Style & Naming Conventions

Use standard Rust formatting and keep code ASCII unless a file already requires Unicode. Run `cargo fmt` and `cargo clippy --workspace --all-targets` before submitting Rust changes. Prefer small, focused crates and explicit names: `serve-legacy`, `server-segv`, `thread-crash`. Keep kernel-facing behavior concrete and avoid hidden magic in setup paths.

## Testing Guidelines

Unit tests live next to Rust code. Scenario-based VM tests live in `crates/vmtest/tests/scenarios/` and use descriptive snake_case names such as `dumpable_off.rs` and `server_legacy_segv.rs`. For kernel-mode changes, add or update a VM scenario instead of relying only on unit tests.

## Important Context For Agents

- `coregate setup` is the source of truth for kernel integration strings. Do not hand-edit example `core_pattern` strings in docs without keeping CLI output aligned.
- Kernel modes are versioned:
  - `handle`: classic pipe helper, no kernel version gate
  - `server-legacy`: `@/path.sock`, requires Linux `>= 6.16`
  - `server`: `@@/path.sock`, requires Linux `>= 6.19`
- `@` and `@@` are different kernel protocols, not cosmetic aliases. Treat them as separate ingress implementations.
- The hot path matters. Avoid adding expensive metadata enrichment before the core stream is drained.
- VM tests are the main safety net for kernel-facing behavior. Prefer extending `crates/vmtest/tests/scenarios/` over adding only mock/unit coverage.
- Guest tools for VM tests are built for `x86_64-unknown-linux-musl` to avoid host/guest glibc mismatch. Do not casually switch that path back to glibc.
- The site in `site/` is plain Hugo with custom layouts, no external theme. Keep it self-contained.

## Security & Configuration Tips

Do not commit generated VM images, kernels, `target/`, `site-public/`, or local caches. Use `coregate setup ...` dry runs before `--apply`, especially for `server-legacy` and `server`, which are kernel-version gated.
