"""Providers for VM test infrastructure."""

VMHostInfo = provider(
    doc = "Configuration for a VM host environment used by vm_test rules.",
    fields = {
        "image": "File: base VM disk image (qcow2)",
        "memory_mib": "int: VM memory in MiB",
        "cpus": "int: number of vCPUs",
    },
)
