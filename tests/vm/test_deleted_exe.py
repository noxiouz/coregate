"""VM test: deleted_exe scenario.

Crashes a binary that deletes itself before the signal arrives.
Coregate should still collect and mark binary_removed=true.
"""

import json
import os
import unittest

RECORDS_JSONL = "/var/lib/coregate/records.jsonl"
CORES_DIR = "/var/lib/coregate/cores"


class DeletedExeTest(unittest.TestCase):

    def setUp(self):
        if not os.path.exists(RECORDS_JSONL):
            self.skipTest(f"{RECORDS_JSONL} not found")

    def test_record_produced(self):
        record = _last_record()
        self.assertEqual(record.get("schema_version"), 1)

    def test_binary_removed_flag(self):
        record = _last_record()
        metadata = record["metadata"]
        self.assertTrue(
            metadata.get("binary_removed"),
            f"binary_removed should be true: {metadata}",
        )

    def test_binary_path_present(self):
        record = _last_record()
        self.assertIsNotNone(
            record["metadata"].get("binary_path"),
            "binary_path should still be present",
        )

    def test_core_file_exists(self):
        self.assertTrue(os.path.isdir(CORES_DIR))
        cores = os.listdir(CORES_DIR)
        self.assertGreater(len(cores), 0, "expected at least one core file")


def _last_record():
    with open(RECORDS_JSONL) as f:
        lines = [l.strip() for l in f if l.strip()]
    return json.loads(lines[-1])


if __name__ == "__main__":
    unittest.main()
