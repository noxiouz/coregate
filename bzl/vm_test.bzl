"""Bazel rules for running tests inside a QEMU VM.

Inspired by Antlir2's vm_test pattern: wraps an inner test target and
executes it inside a QEMU guest using coregate's vmtest infrastructure.

All vm_*_test macros follow the same pattern:
  1. Build an inner test (rust_test, py_test, sh_test) on the host
  2. Wrap it with _vm_test — copies the executable into a VM and runs it there
  3. Propagate guest exit code back to Bazel

Usage:
    load("//bzl:vm_test.bzl", "vm_test", "vm_rust_test", "vm_python_test", "vm_sh_test")

    vm_python_test(
        name = "my_test",
        vm_host = "//tests/vm:debian12",
        srcs = ["test_something.py"],
        deps = ["//some:library"],
        guest_setup = "apt-get install -y something",
    )
"""

load("@rules_rust//rust:defs.bzl", "rust_test")
load("@rules_shell//shell:sh_test.bzl", "sh_test")
load(":providers.bzl", "VMHostInfo")

_GUEST_PLATFORM = "//:linux_x86_64_musl"
_GUEST_RUST_TOOLCHAIN = "@rust_toolchains//:rust_linux_x86_64__x86_64-unknown-linux-musl__stable"

def _transitioned_target(value):
    if type(value) == "list":
        if len(value) != 1:
            fail("expected a single transitioned target, got {}".format(len(value)))
        return value[0]
    return value

def _guest_platform_transition_impl(settings, attr):
    extra_toolchains = list(settings["//command_line_option:extra_toolchains"])
    if _GUEST_RUST_TOOLCHAIN not in extra_toolchains:
        extra_toolchains.append(_GUEST_RUST_TOOLCHAIN)
    return {
        "//command_line_option:extra_toolchains": extra_toolchains,
        "//command_line_option:platforms": [_GUEST_PLATFORM],
    }

_guest_platform_transition = transition(
    implementation = _guest_platform_transition_impl,
    inputs = ["//command_line_option:extra_toolchains"],
    outputs = [
        "//command_line_option:extra_toolchains",
        "//command_line_option:platforms",
    ],
)

# ---------------------------------------------------------------------------
# _vm_test rule: the core — runs any executable inside the VM
# ---------------------------------------------------------------------------

def _vm_test_impl(ctx):
    vm = ctx.attr.vm_host[VMHostInfo]
    test_bin = ctx.executable.test
    runner_bin = ctx.executable._vm_runner
    agent_bin = ctx.executable._vmtest_agent

    data_files = []
    for raw_dep in ctx.attr.data:
        d = _transitioned_target(raw_dep)
        data_files.extend(d.files.to_list())

    # Write guest_setup to a file to avoid shell quoting issues.
    guest_setup_file = None
    if ctx.attr.guest_setup:
        guest_setup_file = ctx.actions.declare_file(ctx.label.name + "_guest_setup.sh")
        ctx.actions.write(
            output = guest_setup_file,
            content = "#!/bin/sh\nset -eu\n" + ctx.attr.guest_setup + "\n",
            is_executable = True,
        )

    script = ctx.actions.declare_file(ctx.label.name + "_vm_runner.sh")

    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        'exec {runner} run-test \\'.format(runner = runner_bin.short_path),
        '  --image {image} \\'.format(image = vm.image.short_path),
        '  --agent {agent} \\'.format(agent = agent_bin.short_path),
        '  --test-binary {test} \\'.format(test = test_bin.short_path),
        '  --memory-mib {mem} \\'.format(mem = vm.memory_mib),
        '  --cpus {cpus} \\'.format(cpus = vm.cpus),
        '  --timeout {timeout} \\'.format(timeout = ctx.attr.timeout_secs),
    ]

    if vm.kernel:
        lines.append('  --kernel {path} \\'.format(path = vm.kernel.short_path))

    if vm.initrd:
        lines.append('  --initrd {path} \\'.format(path = vm.initrd.short_path))

    if vm.append:
        lines.append("  --append '{append}' \\".format(append = vm.append))

    if guest_setup_file:
        lines.append('  --guest-setup-file {path} \\'.format(path = guest_setup_file.short_path))

    for f in data_files:
        lines.append('  --extra-file {path} \\'.format(path = f.short_path))

    lines[-1] = lines[-1].rstrip(" \\")
    lines.append("")

    ctx.actions.write(
        output = script,
        content = "\n".join(lines),
        is_executable = True,
    )

    all_runfiles_files = [vm.image, test_bin, runner_bin, agent_bin] + data_files
    if vm.kernel:
        all_runfiles_files.append(vm.kernel)
    if vm.initrd:
        all_runfiles_files.append(vm.initrd)
    if guest_setup_file:
        all_runfiles_files.append(guest_setup_file)

    runfiles = ctx.runfiles(files = all_runfiles_files)
    runfiles = runfiles.merge(ctx.attr._vm_runner[DefaultInfo].default_runfiles)
    runfiles = runfiles.merge(_transitioned_target(ctx.attr._vmtest_agent)[DefaultInfo].default_runfiles)
    runfiles = runfiles.merge(_transitioned_target(ctx.attr.test)[DefaultInfo].default_runfiles)

    return [DefaultInfo(
        executable = script,
        runfiles = runfiles,
    )]

_vm_test = rule(
    implementation = _vm_test_impl,
    doc = "Runs a test executable inside a QEMU VM.",
    test = True,
    attrs = {
        "test": attr.label(
            executable = True,
            cfg = _guest_platform_transition,
            mandatory = True,
            doc = "Test executable to run inside the VM.",
        ),
        "vm_host": attr.label(providers = [VMHostInfo], mandatory = True),
        "timeout_secs": attr.int(default = 300),
        "guest_setup": attr.string(
            default = "",
            doc = "Shell commands to run in guest before the test binary.",
        ),
        "data": attr.label_list(
            allow_files = True,
            cfg = _guest_platform_transition,
            doc = "Additional files to copy into the VM.",
        ),
        "_vm_runner": attr.label(
            default = "//crates/vmtest:vmtest",
            executable = True,
            cfg = "exec",
        ),
        "_vmtest_agent": attr.label(
            default = "//crates/vmtest:vmtest-agent",
            executable = True,
            cfg = _guest_platform_transition,
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)

# ---------------------------------------------------------------------------
# Convenience macros — all follow the same pattern:
#   1. Build inner test with "manual" tag (so it's not run on host directly)
#   2. Wrap with _vm_test
# ---------------------------------------------------------------------------

def _split_test_tags(kwargs):
    """Return wrapper tags and inner tags, keeping the inner target manual."""
    tags = list(kwargs.pop("tags", []))
    inner_tags = list(tags)
    if "manual" not in inner_tags:
        inner_tags.append("manual")
    return tags, inner_tags

def vm_test(name, vm_host, test, timeout_secs = 300, guest_setup = "", data = [], **kwargs):
    """Generic vm_test — wraps an existing executable to run inside a VM."""
    _vm_test(
        name = name,
        test = test,
        vm_host = vm_host,
        timeout_secs = timeout_secs,
        guest_setup = guest_setup,
        data = data,
        **kwargs
    )

def vm_rust_test(name, vm_host, timeout_secs = 300, guest_setup = "", data = [], **kwargs):
    """Builds a rust_test, then runs it inside a QEMU VM."""
    inner_name = name + "_vm_inner"
    wrapper_tags, inner_tags = _split_test_tags(kwargs)
    rust_test(
        name = inner_name,
        tags = inner_tags,
        **kwargs
    )
    _vm_test(
        name = name,
        test = ":" + inner_name,
        vm_host = vm_host,
        timeout_secs = timeout_secs,
        guest_setup = guest_setup,
        data = data,
        tags = wrapper_tags,
    )

def vm_python_test(name, vm_host, timeout_secs = 300, guest_setup = "", data = [], **kwargs):
    """Runs a Python source file inside a QEMU VM using guest /usr/bin/python3.

    Args:
        name: Target name.
        vm_host: Label of a vm_host() target.
        timeout_secs: Total allowed execution time.
        guest_setup: Shell commands to run in guest before the test.
        data: Additional files to copy into the VM.
        **kwargs: Source-only test args. deps are intentionally unsupported
            until vmtest copies Bazel runfiles into the guest.
    """
    inner_name = name + "_vm_inner"
    wrapper_tags, inner_tags = _split_test_tags(kwargs)

    srcs = kwargs.pop("srcs", [])
    if not srcs:
        fail("vm_python_test requires at least one source file")
    main = kwargs.pop("main", srcs[0])
    deps = kwargs.pop("deps", [])
    if deps:
        fail("vm_python_test does not support deps yet; use source-only tests")

    # Keep kwargs narrow so the generated launcher remains a plain guest script.
    if kwargs:
        fail("unsupported vm_python_test kwargs: {}".format(sorted(kwargs.keys())))

    native.genrule(
        name = inner_name,
        outs = [inner_name + ".sh"],
        cmd = "cat > $@ <<'EOF'\n#!/usr/bin/env sh\nset -eu\nexec /usr/bin/python3 /usr/local/bin/{main}\nEOF\nchmod +x $@".format(
            main = main.rsplit("/", 1)[-1],
        ),
        executable = True,
        tags = inner_tags,
    )
    _vm_test(
        name = name,
        test = ":" + inner_name,
        vm_host = vm_host,
        timeout_secs = timeout_secs,
        guest_setup = guest_setup,
        data = data + srcs,
        tags = wrapper_tags,
    )

def vm_sh_test(name, vm_host, timeout_secs = 300, guest_setup = "", data = [], **kwargs):
    """Builds a sh_test, then runs it inside a QEMU VM."""
    inner_name = name + "_vm_inner"
    wrapper_tags, inner_tags = _split_test_tags(kwargs)
    sh_test(
        name = inner_name,
        tags = inner_tags,
        **kwargs
    )
    _vm_test(
        name = name,
        test = ":" + inner_name,
        vm_host = vm_host,
        timeout_secs = timeout_secs,
        guest_setup = guest_setup,
        data = data,
        tags = wrapper_tags,
    )
