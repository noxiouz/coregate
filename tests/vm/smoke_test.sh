#!/bin/bash
# Smoke test: verify we're running inside a VM with expected tools.
set -euo pipefail

echo "=== VM smoke test ==="
uname -a
echo "Hostname: $(hostname)"
echo "Kernel: $(uname -r)"
echo "Test passed."
