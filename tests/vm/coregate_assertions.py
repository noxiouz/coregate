"""Shared assertions for VM-side Coregate Python tests."""

import json
import os
import unittest

RECORDS_JSONL = "/var/lib/coregate/records.jsonl"
CORES_DIR = "/var/lib/coregate/cores"


def last_record():
    with open(RECORDS_JSONL) as f:
        lines = [line.strip() for line in f if line.strip()]
    if not lines:
        raise AssertionError(f"{RECORDS_JSONL} is empty")
    return json.loads(lines[-1])


def require_record_file(testcase: unittest.TestCase):
    if not os.path.exists(RECORDS_JSONL):
        testcase.skipTest(f"{RECORDS_JSONL} not found")


def assert_stored_core(testcase: unittest.TestCase, record):
    testcase.assertTrue(os.path.isdir(CORES_DIR), f"{CORES_DIR} should exist")
    testcase.assertGreater(len(os.listdir(CORES_DIR)), 0, "expected at least one core file")
    testcase.assertEqual(record.get("schema_version"), 3)
    testcase.assertEqual(record["dump"].get("reason"), "stored", record)
    location = record["core"].get("location")
    testcase.assertIsInstance(location, str, record)
    testcase.assertTrue(location.startswith("file://"), record)
