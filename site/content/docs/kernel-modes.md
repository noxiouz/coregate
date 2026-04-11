---
title: Kernel Modes
weight: 20
summary: Track handle and socket coredump ingress modes.
---

## `handle`

`handle` is the classic Linux `core_pattern` pipe helper mode. The kernel
invokes `coregate` directly and streams the core dump to `stdin`.

Use it when you need the broadest compatibility.

Example:

```text
|/usr/local/bin/coregate handle %P %i %I %s %t %d %E /etc/coregate/config.json
```

## `serve-legacy`

`serve-legacy` is the older socket server mode. It is configured with a
`core_pattern` starting with `@` and requires Linux 6.16 or newer.

Example:

```text
@/run/coregate-coredump.socket
```

This mode is exposed as `coregate serve-legacy` and feeds the same module
runtime as handle mode.

## `serve`

`serve` is the newer protocol socket mode. It is configured with a
`core_pattern` starting with `@@` and requires Linux 6.19 or newer.

Example:

```text
@@/run/coregate-coredump.socket
```

This mode is exposed as `coregate serve` and feeds the same module runtime as
handle mode.

## Socket Activation

Both socket modes support systemd socket activation. When `LISTEN_PID` and
`LISTEN_FDS` describe exactly one inherited listener, Coregate uses fd `3`
instead of binding the path itself. The activated socket must be a listening
Unix stream socket and its path must match `--socket-address`.

Example `coregate.socket`:

```ini
[Socket]
ListenStream=/run/coregate-coredump.socket
SocketMode=0600

[Install]
WantedBy=sockets.target
```

Example 6.19+ service:

```ini
[Service]
ExecStart=/usr/local/bin/coregate serve \
    --socket-address @@/run/coregate-coredump.socket \
    --config /etc/coregate/config.json
```

For legacy mode, use the same socket unit with:

```ini
[Service]
ExecStart=/usr/local/bin/coregate serve-legacy \
    --socket-address @/run/coregate-coredump.socket \
    --config /etc/coregate/config.json
```

## Choosing a Mode

| Mode | Kernel | Pattern | Current status |
| --- | --- | --- | --- |
| `handle` | broad support | `|... coregate handle ...` | binary command |
| `serve-legacy` | `>= 6.16` | `@/path.sock` | binary command |
| `serve` | `>= 6.19` | `@@/path.sock` | binary command |
