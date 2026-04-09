"""Rule for declaring a VM host configuration."""

load(":providers.bzl", "VMHostInfo", "VMKernelInfo")

def _vm_host_impl(ctx):
    kernel = ctx.file.kernel
    initrd = ctx.file.initrd

    # vm_kernel provides both kernel and initrd from a single extraction target.
    if ctx.attr.vm_kernel:
        if kernel or initrd:
            fail("Cannot specify both vm_kernel and explicit kernel/initrd")
        ki = ctx.attr.vm_kernel[VMKernelInfo]
        kernel = ki.vmlinuz
        initrd = ki.initrd

    if bool(kernel) != bool(initrd):
        fail("kernel and initrd must either both be set or both be unset")

    return [VMHostInfo(
        image = ctx.file.image,
        kernel = kernel,
        initrd = initrd,
        append = ctx.attr.append,
        memory_mib = ctx.attr.memory_mib,
        cpus = ctx.attr.cpus,
    )]

vm_host = rule(
    implementation = _vm_host_impl,
    doc = """Declares a VM host configuration (disk image + machine spec) for use with vm_test.

Boot modes:
  1. Disk boot (default): GRUB inside the qcow2 boots the kernel.
  2. Direct boot: pass kernel + initrd explicitly, or use vm_kernel
     from vm_kernel_from_image() to extract them from the disk image.
     Direct boot is faster since it skips GRUB/BIOS.
""",
    attrs = {
        "image": attr.label(
            allow_single_file = [".qcow2", ".img"],
            mandatory = True,
            doc = "Base VM disk image (qcow2 or raw). An overlay is created at test time.",
        ),
        "vm_kernel": attr.label(
            providers = [VMKernelInfo],
            doc = "Target providing VMKernelInfo (e.g. from vm_kernel_from_image). " +
                  "Mutually exclusive with kernel/initrd.",
        ),
        "kernel": attr.label(
            allow_single_file = True,
            doc = "Kernel image for direct boot. Requires initrd.",
        ),
        "initrd": attr.label(
            allow_single_file = True,
            doc = "Initrd image for direct boot. Requires kernel.",
        ),
        "append": attr.string(
            default = "",
            doc = "Extra kernel command-line parameters (used with kernel/initrd).",
        ),
        "memory_mib": attr.int(
            default = 2048,
            doc = "VM memory in MiB.",
        ),
        "cpus": attr.int(
            default = 2,
            doc = "Number of vCPUs.",
        ),
    },
)
