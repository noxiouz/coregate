"""VM test: thread_crash scenario.

Crashes a non-main thread named "crash-worker". Coregate should capture
the crashing thread's name and tid (which differs from pid).
"""

import json
import os
import unittest

RECORDS_JSONL = "/var/lib/coregate/records.jsonl"
CORES_DIR = "/var/lib/coregate/cores"


class ThreadCrashTest(unittest.TestCase):

    def setUp(self):
        if not os.path.exists(RECORDS_JSONL):
            self.skipTest(f"{RECORDS_JSONL} not found")

    def test_record_produced(self):
        record = _last_record()
        self.assertEqual(record.get("schema_version"), 3)

    def test_thread_name(self):
        record = _last_record()
        metadata = record["metadata"]
        self.assertEqual(
            metadata.get("thread_name"), "crash-worker",
            f"thread_name should be crash-worker: {metadata}",
        )

    def test_tid_differs_from_pid(self):
        record = _last_record()
        metadata = record["metadata"]
        pid = metadata.get("pid")
        tid = metadata.get("tid")
        self.assertIsNotNone(pid)
        self.assertIsNotNone(tid)
        self.assertNotEqual(tid, pid,
                            "tid should differ from pid for a non-main thread crash")

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
