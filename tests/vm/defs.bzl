"""Helpers for VM test BUILD targets."""

# Common tags for all VM tests.
VM_TAGS = [
    "exclusive",
    "manual",
    "requires-vm",
]

# Common data deps for handle-mode scenarios.
HANDLE_DATA = [
    "//tests/vm:coregate_guest",
    "//crates/vmtest:victim-crash",
    "coregate-config.json",
]

SERVER_SOCKET = "/run/coregate-coredump.socket"

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

def server_guest_setup(mode, crash_command, config_file = "coregate-config.json"):
    """Build a guest_setup string for server or server-legacy scenarios."""
    if mode == "server":
        socket_address = "@@" + SERVER_SOCKET
        serve_command = "serve"
    elif mode == "server-legacy":
        socket_address = "@" + SERVER_SOCKET
        serve_command = "serve-legacy"
    else:
        fail("unsupported server mode: {}".format(mode))

    return " && ".join([
        "install -d -m0755 /etc/coregate /var/lib/coregate /var/lib/coregate/cores",
        "install -m0644 /usr/local/bin/{config} /etc/coregate/config.json".format(config = config_file),
        "rm -f /var/lib/coregate/serve.log {socket}".format(socket = SERVER_SOCKET),
        "/usr/local/bin/coregate setup {mode} --apply".format(mode = mode),
        (
            "(nohup /usr/local/bin/coregate {serve} --socket-address {socket} " +
            "--config /etc/coregate/config.json " +
            ">/var/lib/coregate/serve.log 2>&1 </dev/null &)"
        ).format(serve = serve_command, socket = socket_address),
        "sleep 1",
        "pgrep -f '/usr/local/bin/coregate {serve}' >/dev/null || (cat /var/lib/coregate/serve.log >&2; exit 1)".format(serve = serve_command),
        "ulimit -c unlimited; {cmd}".format(cmd = crash_command),
        "sleep 2",
        "cat /var/lib/coregate/serve.log >&2 || true",
    ])
