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
