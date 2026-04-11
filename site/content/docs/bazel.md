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
bazel build //:coregate

# Build the guest/static variant used by VM tests
bazel build --config=musl //:coregate_guest
```

The Bazel `coregate` target enables the default SQLite metadata path and keeps
collector-side BPF readout disabled. BPF stack support is opt-in and tagged
`manual` so `bazel build //...` does not build `libbpf-sys`.

The `coregate_guest` target is the static musl variant used by VM tests. It
keeps collector-side BPF readout and SQLite disabled so it does not require
linking C dependencies into the guest binary.

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
    manifests = ["//:Cargo.toml"],
)
```

After adding a new dependency to any `Cargo.toml`, repin:

```bash
CARGO_BAZEL_REPIN=1 bazel sync --only=crates
```

## Cross-compilation

The musl config produces fully static `x86_64-unknown-linux-musl` Rust
binaries when the target does not need host-built C objects:

```bash
bazel build --config=musl //:coregate_guest
bazel build --config=musl //crates/vmtest:vmtest-agent
```

This is configured via a repository-local `musl` platform constraint, a
rules_rust musl repository set in `MODULE.bazel`, and `.bazelrc`'s
`--config=musl` extra toolchain.

Bazel VM tests apply this guest platform automatically to guest-side labels.
The host-side `vmtest` runner stays in exec configuration.

QEMU-backed VM tests are tagged `manual`, so default `bazel test //...` does
not require KVM or downloaded VM images. Run a scenario explicitly when needed:

```bash
bazel test //tests/vm:vm_tests --test_output=errors
bazel test //tests/vm:core_pattern_segv --test_output=streamed
bazel test //tests/vm:server_segv //tests/vm:server_legacy_segv --test_output=errors
```

`bazel test //tests/vm/...` also skips the VM scenarios because they are
`manual`. Use `//tests/vm:vm_tests` to run the explicit suite.

The socket-mode targets use `//tests/vm:linux_6_19_kernel`, which Bazel
generates from the Debian rootfs with `vm_kernel_from_guest_packages`. The rule
boots the rootfs, installs the requested Ubuntu mainline kernel packages, runs
`update-initramfs`, and exports declared `vmlinuz`/`initrd` outputs for direct
QEMU boot. Do not replace this with `.cache/` source inputs.

## Crate targets

| Crate | Target | Type |
|-------|--------|------|
| root package | `//:coregate` | shipped binary |
| root package | `//:coregate_guest` | no-SQLite VM guest binary |
| `crates/coregate` | `//crates/coregate:coregate_lib` | reusable library |
| `crates/coregate-cli` | `//crates/coregate-cli:coregate_cli_lib` | reusable CLI front-end |
| `crates/bpf-stack` | `//crates/bpf-stack:coregate-bpf-stack` | optional/manual library |
| `crates/symbolizer-proto` | `//crates/symbolizer-proto` | library |
| `crates/vmtest` | `//crates/vmtest:vmtest` | harness binary + library |
| `crates/vmtest` | `//crates/vmtest:vmtest-agent` | guest agent binary |
| `crates/vmtest` | `//crates/vmtest:victim-crash` | guest crash fixture binary |
| `crates/vmtest-scenarios` | `//crates/vmtest-scenarios:scenarios_main` | VM scenario tests |
| `crates/xtask` | `//crates/xtask` | binary |
