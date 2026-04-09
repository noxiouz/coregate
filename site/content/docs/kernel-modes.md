---
title: Kernel Modes
weight: 20
summary: Choose between `handle`, `serve-legacy`, and `serve` based on kernel support and integration style.
---

## `handle`

`handle` is the classic Linux `core_pattern` pipe helper mode. The kernel invokes `coregate` directly and streams the core dump to `stdin`.

Use it when you need the broadest compatibility.

## `serve-legacy`

`serve-legacy` is the older socket server mode. It is configured with a `core_pattern` starting with `@` and requires Linux 6.16 or newer.

Example:

```text
@/run/coregate-coredump.socket
```

## `serve`

`serve` is the newer protocol socket mode. It is configured with a `core_pattern` starting with `@@` and requires Linux 6.19 or newer.

Example:

```text
@@/run/coregate-coredump.socket
```

## Choosing a mode

| Mode | Kernel | Pattern | Notes |
| --- | --- | --- | --- |
| `handle` | broad support | `|... coregate handle ...` | simplest integration |
| `serve-legacy` | `>= 6.16` | `@/path.sock` | stream socket mode |
| `serve` | `>= 6.19` | `@@/path.sock` | protocol socket mode |
