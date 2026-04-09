"""Rule for declaring a VM host configuration."""

load(":providers.bzl", "VMHostInfo")

def _vm_host_impl(ctx):
    return [VMHostInfo(
        image = ctx.file.image,
        memory_mib = ctx.attr.memory_mib,
        cpus = ctx.attr.cpus,
    )]

vm_host = rule(
    implementation = _vm_host_impl,
    doc = "Declares a VM host configuration (disk image + machine spec) for use with vm_test.",
    attrs = {
        "image": attr.label(
            allow_single_file = [".qcow2", ".img"],
            mandatory = True,
            doc = "Base VM disk image (qcow2 or raw). An overlay is created at test time.",
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
