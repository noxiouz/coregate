---
title: Configuration
weight: 30
summary: Configure storage, sinks, rate limits, and ordered overrides.
---

Coregate reads JSON and parses it into protobuf-generated Rust types.

Current configuration covers:

- `default` config applied to every crash
- ordered `overrides` merged on top of the default
- compression (`none`, `zstd`, `xz`)
- sparse file behavior
- minimum free-space reserve on the target filesystem
- local rate limits
- JSONL metadata sink
- optional SQLite metadata sink
- stack symbolization mode: local, none, or remote HTTP

## Example

```json
{
  "default": {
    "output_dir": "/var/lib/coregate/cores",
    "metadata_jsonl": "/var/lib/coregate/records.jsonl",
    "metadata_sqlite": "/var/lib/coregate/records.sqlite",
    "respect_dumpable": true,
    "symbolizer": {
      "mode": "local"
    },
    "core": {
      "compression": "zstd",
      "sparse": false,
      "min_free_percent": 10
    }
  },
  "overrides": [
    {
      "matcher": {
        "runtime": "python"
      },
      "config": {
        "package_lookup": true
      }
    }
  ]
}
```

## Override model

Coregate applies:

1. `default`
2. every matching entry in `overrides`
3. later matching overrides win

## Main fields

### `default`

Baseline collector configuration applied to every crash before overrides.

### `overrides`

Ordered list of matcher-based config overlays. A later matching override replaces earlier values for the same fields.

## Collector config fields

### `output_dir`

Directory used for stored core files.

### `metadata_jsonl`

Append-only JSONL file containing crash records.

### `metadata_sqlite`

Optional SQLite file containing indexed crash records. Use an empty string to disable it explicitly.

### `limit_state_file`

Persistent local rate-limit state file.

### `respect_dumpable`

When `true`, Coregate rejects dumps unless the crashing task is dumpable.

### `package_lookup`

When `true`, Coregate tries to resolve package ownership and version through `dpkg` or `rpm`.

### `symbolizer`

Controls post-capture stack symbolization.

- `mode: "none"`: keep raw frames only
- `mode: "local"`: symbolize in the collector with `blazesym`
- `mode: "http"`: normalize locally and send the stack to a remote HTTP service

## `core`

Storage policy for core files.

- `compression`: `none`, `zstd`, or `xz`
- `sparse`: sparse uncompressed writes where possible
- `min_free_percent`: minimum free space that must remain on the target filesystem

## `rate_limit`

Per-machine rate limiting.

- `default_max_per_minute`: fallback limit when no rule matches
- `rules`: per-binary or per-cgroup rule list

Each rule supports:

- `binary`: exact binary name match
- `cgroup_prefix`: prefix match against the collected cgroup path
- `max_per_minute`: allowed dumps per minute for matching crashes

## Override matchers

Current matchers include:

- `binary_name`
- `cgroup_prefix`
- `runtime`
- `signal`

See the repo example at `docs/config.example.json`.
