"""VM test: server_segv scenario using Linux 6.19 @@ protocol."""

import unittest

from coregate_assertions import assert_stored_core, last_record, require_record_file


class ServerSegvTest(unittest.TestCase):

    def setUp(self):
        require_record_file(self)

    def test_server_mode_stores_core(self):
        assert_stored_core(self, last_record())


if __name__ == "__main__":
    unittest.main()
