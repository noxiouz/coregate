---
title: Configuration
weight: 30
---

Coregate reads JSON and parses it into protobuf-generated Rust types.

Current configuration covers:

- default storage settings
- compression (`none`, `zstd`, `xz`)
- sparse file behavior
- minimum free-space reserve on the target filesystem
- local rate limits
- JSONL metadata sink
- optional SQLite metadata sink

## Example

```json
{
  "respect_dumpable": true,
  "package_lookup": false,
  "core": {
    "output_dir": "/var/lib/coregate/cores",
    "compression": "zstd",
    "sparse": false,
    "min_free_percent": 10
  },
  "metadata_jsonl": "/var/lib/coregate/records.jsonl",
  "metadata_sqlite": "/var/lib/coregate/records.sqlite"
}
```

See the repo example at `docs/config.example.json`.
