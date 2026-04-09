---
title: Bazel Build
weight: 40
summary: Build all crates with Bazel, manage dependencies via crate_universe, and cross-compile for musl.
---

Coregate supports building with both Cargo and Bazel.
Bazel is used for hermetic builds, VM-based integration tests, and CI.

## Prerequisites

- [Bazelisk](https://github.com/bazelbuild/bazelisk) or Bazel 9+
- Rust toolchain is managed by `rules_rust` (no manual install needed)

## Building

```bash
# Build everything
bazel build //...

# Build the main binary
bazel build //crates/cli:coregate

# Build for musl (static binary)
bazel build --config=musl //crates/cli:coregate
```

## Project structure

```
MODULE.bazel          # bzlmod dependencies (rules_rust, rules_python, etc.)
BUILD.bazel           # Root package, platform definitions
.bazelrc              # Default build flags
.bazelversion         # Pins Bazel version

crates/*/BUILD.bazel  # One per crate
bzl/                  # Custom Bazel rules for VM testing
tests/vm/             # VM-based integration tests
```

## Dependency management

External Rust dependencies are resolved by `crate_universe` from the Cargo workspace:

```python
# MODULE.bazel
crate.from_cargo(
    name = "crates",
    cargo_lockfile = "//:Cargo.lock",
    manifests = ["//:Cargo.toml", "//crates/cli:Cargo.toml", ...],
)
```

After adding a new dependency to any `Cargo.toml`, repin:

```bash
CARGO_BAZEL_REPIN=1 bazel sync --only=crates
```

## Cross-compilation

The musl config produces fully static `x86_64-unknown-linux-musl` binaries:

```bash
bazel build --config=musl //crates/cli:coregate
```

This is configured via an extra target triple in `MODULE.bazel` and a
platform definition in the root `BUILD.bazel`.

## Crate targets

| Crate | Target | Type |
|-------|--------|------|
| `crates/cli` | `//crates/cli:coregate` | binary |
| `crates/corefile` | `//crates/corefile` | library |
| `crates/kernel` | `//crates/kernel` | library |
| `crates/limit` | `//crates/limit` | library |
| `crates/meta` | `//crates/meta` | library |
| `crates/store` | `//crates/store` | library |
| `crates/telemetry` | `//crates/telemetry` | library |
| `crates/vmtest` | `//crates/vmtest:vmtest` | binary + library |
| `crates/vmtest-agent` | `//crates/vmtest-agent:vmtest-agent` | binary |
| `crates/vmtest-protocol` | `//crates/vmtest-protocol` | library |
| `crates/victim-crash` | `//crates/victim-crash` | binary (test fixture) |
| `crates/xtask` | `//crates/xtask` | binary |
