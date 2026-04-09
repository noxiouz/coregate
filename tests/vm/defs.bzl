"""Helpers for VM test BUILD targets."""

# Common tags for all VM tests.
VM_TAGS = [
    "exclusive",
    "requires-vm",
]

# Common data deps for handle-mode scenarios.
HANDLE_DATA = [
    "//crates/cli:coregate",
    "//crates/victim-crash",
    "coregate-config.json",
]

def handle_guest_setup(crash_command, config_file = "coregate-config.json"):
    """Build a guest_setup string for handle-mode scenarios.

    Installs coregate as the core_pattern handler, triggers the given crash
    command, and waits for collection to finish.
    """
    return " && ".join([
        "install -d -m0755 /etc/coregate /var/lib/coregate /var/lib/coregate/cores",
        "install -m0644 /usr/local/bin/{config} /etc/coregate/config.json".format(config = config_file),
        "printf '%s' '|/usr/local/bin/coregate handle %P %i %I %s %t %d %E /etc/coregate/config.json' > /proc/sys/kernel/core_pattern",
        "sysctl -w kernel.core_pipe_limit=16",
        "ulimit -c unlimited; {cmd}".format(cmd = crash_command),
        "sleep 2",
    ])
