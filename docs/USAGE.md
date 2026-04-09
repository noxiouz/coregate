# Usage

## Build

```bash
cargo build -p coregate
cargo build -p coregate --no-default-features
cargo build -p coregate-bpf
```

## Handle Mode

```bash
coregate handle 1234 1234 1234 11 1710000000 1 /usr/bin/my-app ./docs/config.example.json < corefile.bin
```

Canonical `core_pattern` used by `coregate setup handle`:

```text
|/usr/local/bin/coregate handle %P %i %I %s %t %d %E /etc/coregate/config.json
```

## Kernel Setup

Dry run:

```bash
cargo run -p coregate -- setup handle
cargo run -p coregate -- setup server-legacy
cargo run -p coregate -- setup server
```

Apply:

```bash
sudo cargo run -p coregate -- setup handle --apply
sudo cargo run -p coregate -- setup server-legacy --apply
```

Notes:

- config path default: `/etc/coregate/config.json`
- legacy socket default: `@/run/coregate-coredump.socket`
- protocol socket default: `@@/run/coregate-coredump.socket`
- `setup server-legacy` requires Linux `>= 6.16`
- `setup server` requires Linux `>= 6.19`

## BPF Stack Tracer

How it works:

- a separate `coregate-bpf` utility attaches `kprobe/do_coredump`
- the BPF program stores up to 32 user return addresses in a pinned LRU map keyed by global pid/tgid
- `coregate` reads and deletes that entry during crash handling
- user space then adds best-effort `blazesym` symbols plus normalized file offsets for later remote symbolization

Install the pinned tracer objects:

```bash
sudo cargo run -p coregate-bpf -- install
```

Replace existing pinned objects:

```bash
sudo cargo run -p coregate-bpf -- install --force
```

Inspect tracer state:

```bash
sudo cargo run -p coregate -- debug-bpf-stats --json
sudo cargo run -p coregate -- debug-bpf-stack <pid> --json
```

Remove the pinned tracer objects:

```bash
sudo cargo run -p coregate-bpf -- remove
```

Notes:

- BPF objects are pinned under `/sys/fs/bpf/coregate`
- the tracer captures up to 32 raw user-space return addresses keyed by global pid/tgid
- `coregate` reads and deletes the stack entry after a successful lookup
- stack records now carry:
  - best-effort live `blazesym` symbols for the crashing process
  - normalized file-offset metadata suitable for later remote/file-based symbolization
- current validation was done on Linux `6.6.87.2-microsoft-standard-WSL2`

## VM Tests

```bash
cargo run -p xtask -- vmtest fetch-image
cargo run -p xtask -- vmtest build-guest-tools
cargo run -p xtask -- vmtest run --scenario all
```

Run one scenario:

```bash
cargo run -p xtask -- vmtest run --scenario core-pattern-segv
cargo run -p xtask -- vmtest run --scenario deleted-exe
```

Socket-mode scenarios require an explicit guest kernel:

```bash
COREGATE_VM_KERNEL=/path/to/bzImage \
COREGATE_VM_INITRD=/path/to/initrd.img \
cargo run -p xtask -- vmtest run --scenario server-legacy-segv

COREGATE_VM_KERNEL=/path/to/bzImage \
COREGATE_VM_INITRD=/path/to/initrd.img \
cargo run -p xtask -- vmtest run --scenario server-segv
```

## Website

The Hugo site lives under `site/` and is deployed with
`.github/workflows/pages.yml`.

Local build:

```bash
.cache/tools/hugo/hugo --source site --destination ../site-public --minify
```
