import unittest
from netils import build_byte_string
from chewie.eap import Eap, EapIdentity, EapMd5Challenge

class EapTestCase(unittest.TestCase):
    def test_auth_8021x_identity_parses(self):
        packed_message = build_byte_string("0101000501")
        message = Eap.parse(packed_message)
        self.assertEqual(message.packet_id, 1)
        self.assertEqual(message.identity, "")

    def test_auth_8021x_md5_challenge_parses(self):
        packed_message = build_byte_string("0201002204103a535f0ee8c6b34fe714aa7dad9a0e154a6f686e2e4d63477569726b")
        message = Eap.parse(packed_message)
        self.assertEqual(message.packet_id, 1)
        self.assertEqual(message.challenge, build_byte_string("3a535f0ee8c6b34fe714aa7dad9a0e15"))
        self.assertEqual(message.extra_data, b"John.McGuirk")

    def test_auth_8021x_identity_packs(self):
        expected_packed_message = build_byte_string("0101000501")
        eap = EapIdentity(Eap.REQUEST, 1, "")
        packed_message = eap.pack()
        self.assertEqual(expected_packed_message, packed_message)

    def test_auth_8021x_md5_challenge_packs(self):
        expected_packed_message = build_byte_string("0201002204103a535f0ee8c6b34fe714aa7dad9a0e154a6f686e2e4d63477569726b")
        eap = EapMd5Challenge(Eap.RESPONSE, 1, build_byte_string("3a535f0ee8c6b34fe714aa7dad9a0e15"), b"John.McGuirk")
        packed_message = eap.pack()
        self.assertEqual(expected_packed_message, packed_message)
