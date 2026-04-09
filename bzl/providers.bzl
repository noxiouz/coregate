"""Providers for VM test infrastructure."""

VMHostInfo = provider(
    doc = "Configuration for a VM host environment used by vm_test rules.",
    fields = {
        "image": "File: base VM disk image (qcow2)",
        "kernel": "File or None: kernel image for direct boot (requires initrd)",
        "initrd": "File or None: initrd for direct boot (requires kernel)",
        "append": "string: extra kernel command-line parameters",
        "memory_mib": "int: VM memory in MiB",
        "cpus": "int: number of vCPUs",
    },
)

VMKernelInfo = provider(
    doc = "Kernel + initrd pair extracted from a disk image or package.",
    fields = {
        "vmlinuz": "File: kernel image (vmlinuz)",
        "initrd": "File: initrd image",
    },
)
