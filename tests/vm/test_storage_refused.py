"""VM test: storage_refused scenario.

Uses a config with min_free_percent=100 so coregate always refuses
to store the core file. A record should still be written with a
storage_refused reason.
"""

import json
import os
import unittest

RECORDS_JSONL = "/var/lib/coregate/records.jsonl"
CORES_DIR = "/var/lib/coregate/cores"


class StorageRefusedTest(unittest.TestCase):

    def setUp(self):
        if not os.path.exists(RECORDS_JSONL):
            self.skipTest(f"{RECORDS_JSONL} not found")

    def test_record_produced(self):
        record = _last_record()
        self.assertEqual(record.get("schema_version"), 1)

    def test_storage_refused_reason(self):
        record = _last_record()
        rate_limit = record.get("rate_limit", {})
        self.assertEqual(rate_limit.get("key"), "storage",
                         f"expected storage decision key: {record}")
        reason = rate_limit.get("reason", "")
        self.assertTrue(
            reason.startswith("storage_refused:"),
            f"expected storage_refused reason, got: {reason}",
        )

    def test_no_core_file(self):
        """Core file should NOT be stored when storage is refused."""
        if not os.path.isdir(CORES_DIR):
            return
        cores = os.listdir(CORES_DIR)
        self.assertEqual(len(cores), 0, "no core files should be present")


def _last_record():
    with open(RECORDS_JSONL) as f:
        lines = [l.strip() for l in f if l.strip()]
    return json.loads(lines[-1])


if __name__ == "__main__":
    unittest.main()
