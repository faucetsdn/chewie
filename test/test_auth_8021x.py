
# pylint: disable=missing-docstring

import unittest
from chewie.auth_8021x import Auth8021x


class Auth8021xTestCase(unittest.TestCase):
    def test_auth_8021x_parses(self):
        packed_message = bytes.fromhex("01000005010100050100000000")
        message = Auth8021x.parse(packed_message)
        self.assertEqual(message.version, 1)
        self.assertEqual(message.packet_type, 0)
        self.assertEqual(len(message.data), 5)

    def test_auth_8021x_packs(self):
        expected_packed_message = bytes.fromhex("010000050101000501")
        message = Auth8021x(version=1, packet_type=0, data=bytes.fromhex("0101000501"))
        packed_message = message.pack()
        self.assertEqual(expected_packed_message, packed_message)
