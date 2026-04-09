"""VM test: dumpable_off scenario.

Triggers a crash from a process that set PR_SET_DUMPABLE=0.
With respect_dumpable=true, coregate should refuse to collect.
"""

import os
import unittest

RECORDS_JSONL = "/var/lib/coregate/records.jsonl"
CORES_DIR = "/var/lib/coregate/cores"


class DumpableOffTest(unittest.TestCase):

    def test_no_record_produced(self):
        """No crash record should be written when dumpable is off."""
        if not os.path.exists(RECORDS_JSONL):
            return  # file not created at all — correct behavior
        with open(RECORDS_JSONL) as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertEqual(len(lines), 0, "records.jsonl should be empty")

    def test_no_core_file(self):
        """No core file should be stored."""
        if not os.path.isdir(CORES_DIR):
            return  # dir not created — correct
        cores = os.listdir(CORES_DIR)
        self.assertEqual(len(cores), 0, "no core files should be present")


if __name__ == "__main__":
    unittest.main()
