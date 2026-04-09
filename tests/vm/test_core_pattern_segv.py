"""VM test: core_pattern_segv scenario.

This test runs *inside* a QEMU VM via vm_python_test. The guest_setup
configures coregate as the kernel core_pattern handler and triggers a
SIGSEGV crash. This test then inspects the resulting artifacts.
"""

import json
import os
import unittest


RECORDS_JSONL = "/var/lib/coregate/records.jsonl"
CORES_DIR = "/var/lib/coregate/cores"
SQLITE_DB = "/var/lib/coregate/records.sqlite"


class CorePatternSegvTest(unittest.TestCase):
    """Verify coregate correctly collects a SIGSEGV crash via core_pattern."""

    def setUp(self):
        if not os.path.exists(RECORDS_JSONL):
            self.skipTest(f"{RECORDS_JSONL} not found — not running inside a prepared VM")

    def test_record_produced(self):
        """A crash record should be written to records.jsonl."""
        with open(RECORDS_JSONL) as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertGreater(len(lines), 0, "records.jsonl should not be empty")

        record = json.loads(lines[-1])
        self.assertEqual(record.get("schema_version"), 1)

    def test_metadata_fields(self):
        """Key metadata fields should be populated."""
        record = _last_record()
        metadata = record["metadata"]

        self.assertIsNotNone(metadata.get("binary_name"), "binary_name missing")
        self.assertIsNotNone(metadata.get("binary_path"), "binary_path missing")
        self.assertIsNotNone(metadata.get("pid"), "pid missing")
        self.assertIsNotNone(metadata.get("captured_at"), "captured_at missing")

    def test_core_file_exists(self):
        """At least one core file should be stored."""
        self.assertTrue(os.path.isdir(CORES_DIR), f"{CORES_DIR} should exist")
        cores = os.listdir(CORES_DIR)
        self.assertGreater(len(cores), 0, "expected at least one core file")

    def test_sqlite_artifact(self):
        """SQLite metadata database should be created."""
        self.assertTrue(
            os.path.exists(SQLITE_DB),
            f"{SQLITE_DB} should exist",
        )

    def test_rate_limit_allowed(self):
        """The crash should have been allowed by the rate limiter."""
        record = _last_record()
        rate_limit = record.get("rate_limit", {})
        self.assertTrue(rate_limit.get("allowed"), "rate_limit.allowed should be true")


def _last_record():
    with open(RECORDS_JSONL) as f:
        lines = [l.strip() for l in f if l.strip()]
    return json.loads(lines[-1])


if __name__ == "__main__":
    unittest.main()
