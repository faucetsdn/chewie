import unittest
from netils import build_byte_string
from chewy.eap import Eap

class EapTestCase(unittest.TestCase):
    def test_auth_8021x_parses(self):
        packed_message = build_byte_string("0101000501")
        message = Eap.parse(packed_message)
        self.assertEqual(message.code, 1)
        self.assertEqual(message.packet_id, 1)
        self.assertEqual(message.length, 5)
        self.assertEqual(message.packet_type, 1)
