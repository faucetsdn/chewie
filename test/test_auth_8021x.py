import unittest
from netils import build_byte_string
from chewy.auth_8021x import Auth8021x

class Auth8021xTestCase(unittest.TestCase):
    def test_auth_8021x_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e01000005010100050100000000")
        message = Auth8021x.parse(packed_message)
        self.assertEqual(message.version, 1)
        self.assertEqual(message.packet_type, 0)
        self.assertEqual(len(message.data), 5)
