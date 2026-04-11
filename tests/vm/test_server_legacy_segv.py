"""VM test: server_legacy_segv scenario using legacy @ protocol on Linux 6.19."""

import unittest

from coregate_assertions import assert_stored_core, last_record, require_record_file


class ServerLegacySegvTest(unittest.TestCase):

    def setUp(self):
        require_record_file(self)

    def test_server_legacy_mode_stores_core(self):
        assert_stored_core(self, last_record())


if __name__ == "__main__":
    unittest.main()
