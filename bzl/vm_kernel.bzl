"""Rules for extracting kernel and initrd from VM disk images.

Provides vm_kernel_from_image() which uses libguestfs to pull vmlinuz and
initrd out of a qcow2/raw disk image without needing root.

Requires: apt-get install libguestfs-tools

Usage:
    load("//bzl:vm_kernel.bzl", "vm_kernel_from_image")

    vm_kernel_from_image(
        name = "debian12_kernel",
        image = "@debian12_vm_image//file",
    )

    vm_host(
        name = "debian12_direct_boot",
        image = "@debian12_vm_image//file",
        vm_kernel = ":debian12_kernel",
    )
"""

load(":providers.bzl", "VMKernelInfo")

_GUEST_PLATFORM = "//:linux_x86_64_musl"
_GUEST_RUST_TOOLCHAIN = "@rust_toolchains//:rust_linux_x86_64__x86_64-unknown-linux-musl__stable"

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

_EXTRACT_SCRIPT = """\
#!/usr/bin/env bash
set -euo pipefail

IMAGE="$1"
VMLINUZ_OUT="$2"
INITRD_OUT="$3"

if ! command -v guestfish &>/dev/null; then
    echo "ERROR: guestfish not found. Install libguestfs-tools:" >&2
    echo "  sudo apt-get install libguestfs-tools" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# 'direct' backend avoids needing libvirtd; uses /dev/kvm if available.
export LIBGUESTFS_BACKEND=direct

guestfish --ro -a "$IMAGE" -i \\
  glob copy-out /boot/vmlinuz-* "$WORK/" : \\
  glob copy-out /boot/initrd.img-* "$WORK/"

# If the image has multiple kernels pick the latest by version sort.
VMLINUZ=$(ls -v "$WORK"/vmlinuz-* 2>/dev/null | tail -1)
INITRD=$(ls -v "$WORK"/initrd.img-* 2>/dev/null | tail -1)

if [ ! -f "$VMLINUZ" ]; then
    echo "ERROR: no vmlinuz found in $IMAGE" >&2
    ls -la "$WORK"/ >&2
    exit 1
fi
if [ ! -f "$INITRD" ]; then
    echo "ERROR: no initrd.img found in $IMAGE" >&2
    ls -la "$WORK"/ >&2
    exit 1
fi

cp "$VMLINUZ" "$VMLINUZ_OUT"
cp "$INITRD" "$INITRD_OUT"
echo "Extracted: $(basename "$VMLINUZ"), $(basename "$INITRD")"
"""

def _extract_kernel_impl(ctx):
    image = ctx.file.image
    vmlinuz = ctx.actions.declare_file(ctx.label.name + "_vmlinuz")
    initrd = ctx.actions.declare_file(ctx.label.name + "_initrd.img")

    script = ctx.actions.declare_file(ctx.label.name + "_extract.sh")
    ctx.actions.write(output = script, content = _EXTRACT_SCRIPT, is_executable = True)

    ctx.actions.run(
        executable = script,
        arguments = [image.path, vmlinuz.path, initrd.path],
        inputs = [image],
        outputs = [vmlinuz, initrd],
        tools = [script],
        execution_requirements = {
            # libguestfs boots a tiny appliance VM, needs local execution.
            "local": "1",
            "no-sandbox": "1",
        },
        mnemonic = "ExtractKernel",
        progress_message = "Extracting kernel+initrd from %s" % image.short_path,
    )

    return [
        DefaultInfo(files = depset([vmlinuz, initrd])),
        VMKernelInfo(vmlinuz = vmlinuz, initrd = initrd),
    ]

_extract_kernel = rule(
    implementation = _extract_kernel_impl,
    doc = "Extracts vmlinuz and initrd from a VM disk image using libguestfs.",
    attrs = {
        "image": attr.label(
            allow_single_file = [".qcow2", ".img", ".raw"],
            mandatory = True,
            doc = "VM disk image containing /boot/vmlinuz-* and /boot/initrd.img-*.",
        ),
    },
)

def _kernel_from_guest_packages_impl(ctx):
    vmlinuz = ctx.actions.declare_file(ctx.label.name + "_vmlinuz")
    initrd = ctx.actions.declare_file(ctx.label.name + "_initrd.img")
    output_dir = ctx.actions.declare_directory(ctx.label.name + "_out")

    script = ctx.actions.declare_file(ctx.label.name + "_prepare.sh")
    ctx.actions.write(
        output = script,
        is_executable = True,
        content = """\
#!/usr/bin/env bash
set -euo pipefail

{runner} prepare-kernel \\
  --image {image} \\
  --agent {agent} \\
  --memory-mib {memory_mib} \\
  --cpus {cpus} \\
  --mainline-tag {mainline_tag} \\
  --kernel-release {kernel_release} \\
  --package-version {package_version} \\
  --output-dir {output_dir}

cp {output_dir}/vmlinuz-{kernel_release} {vmlinuz}
cp {output_dir}/initrd.img-{kernel_release} {initrd}
""".format(
            runner = ctx.executable._vm_runner.path,
            image = ctx.file.image.path,
            agent = ctx.executable._vmtest_agent.path,
            memory_mib = ctx.attr.memory_mib,
            cpus = ctx.attr.cpus,
            mainline_tag = ctx.attr.mainline_tag,
            kernel_release = ctx.attr.kernel_release,
            package_version = ctx.attr.package_version,
            output_dir = output_dir.path,
            vmlinuz = vmlinuz.path,
            initrd = initrd.path,
        ),
    )

    ctx.actions.run(
        executable = script,
        inputs = [ctx.file.image],
        tools = [
            script,
            ctx.executable._vm_runner,
            ctx.executable._vmtest_agent,
        ],
        outputs = [vmlinuz, initrd, output_dir],
        execution_requirements = {
            "local": "1",
            "no-sandbox": "1",
        },
        mnemonic = "PrepareGuestKernel",
        progress_message = "Preparing guest kernel %s" % ctx.attr.kernel_release,
    )

    return [
        DefaultInfo(files = depset([vmlinuz, initrd])),
        VMKernelInfo(vmlinuz = vmlinuz, initrd = initrd),
    ]

_kernel_from_guest_packages = rule(
    implementation = _kernel_from_guest_packages_impl,
    doc = "Installs kernel packages in a guest rootfs and exports vmlinuz+initrd.",
    attrs = {
        "image": attr.label(
            allow_single_file = [".qcow2", ".img", ".raw"],
            mandatory = True,
            doc = "VM disk image used as the rootfs for package installation.",
        ),
        "mainline_tag": attr.string(mandatory = True),
        "kernel_release": attr.string(mandatory = True),
        "package_version": attr.string(mandatory = True),
        "memory_mib": attr.int(default = 2048),
        "cpus": attr.int(default = 2),
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

def vm_kernel_from_image(name, image, **kwargs):
    """Extract kernel and initrd from a disk image.

    Creates a target that provides VMKernelInfo. Pass it to vm_host(vm_kernel=...).

    Args:
        name: Target name.
        image: Label of a qcow2/raw disk image.
        **kwargs: Passed to the underlying rule (visibility, tags, etc.).
    """
    _extract_kernel(
        name = name,
        image = image,
        **kwargs
    )

def vm_kernel_from_guest_packages(
        name,
        image,
        mainline_tag,
        kernel_release,
        package_version,
        **kwargs):
    """Build kernel+initrd by installing kernel packages inside the guest.

    This is intended for kernel-versioned VM tests. The rule boots the provided
    rootfs with `vmtest`, installs the requested Ubuntu mainline kernel packages,
    runs `update-initramfs`, then exports `/boot/vmlinuz-*` and
    `/boot/initrd.img-*` as declared Bazel outputs.
    """
    _kernel_from_guest_packages(
        name = name,
        image = image,
        mainline_tag = mainline_tag,
        kernel_release = kernel_release,
        package_version = package_version,
        **kwargs
    )
