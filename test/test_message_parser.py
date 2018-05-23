import unittest
from netils import build_byte_string
from chewie.message_parser import MessageParser, MessagePacker, IdentityMessage, Md5ChallengeMessage
from chewie.message_parser import EapolStartMessage, EapolLogoffMessage, SuccessMessage, FailureMessage
from chewie.mac_address import MacAddress
from chewie.eap import Eap

class EapTestCase(unittest.TestCase):
    def test_identity_request_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e010000050101000501000000")
        message = MessageParser.parse(packed_message)
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertEqual(1, message.message_id)
        self.assertEqual(Eap.REQUEST, message.code)
        self.assertEqual("", message.identity)

    def test_identity_response_message_parses(self):
        packed_message = build_byte_string("0180c2000003001422e9545e888e0100001102000011014a6f686e2e4d63477569726b")
        message = MessageParser.parse(packed_message)
        self.assertEqual(MacAddress.from_string("00:14:22:e9:54:5e"), message.src_mac)
        self.assertEqual(0, message.message_id)
        self.assertEqual(Eap.RESPONSE, message.code)
        self.assertEqual("John.McGuirk", message.identity)

    def test_md5_challenge_request_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e01000016010100160410824788d693e2adac6ce15641418228cf0000")
        message = MessageParser.parse(packed_message)
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertEqual(1, message.message_id)
        self.assertEqual(Eap.REQUEST, message.code)
        self.assertEqual(build_byte_string("824788d693e2adac6ce15641418228cf"), message.challenge)
        self.assertEqual(b"", message.extra_data)

    def test_md5_challenge_response_message_parses(self):
        packed_message = build_byte_string("0180c2000003001422e9545e888e010000220201002204103a535f0ee8c6b34fe714aa7dad9a0e154a6f686e2e4d63477569726b")
        message = MessageParser.parse(packed_message)
        self.assertEqual(MacAddress.from_string("00:14:22:e9:54:5e"), message.src_mac)
        self.assertEqual(1, message.message_id)
        self.assertEqual(Eap.RESPONSE, message.code)
        self.assertEqual(build_byte_string("3a535f0ee8c6b34fe714aa7dad9a0e15"), message.challenge)
        self.assertEqual(b"John.McGuirk", message.extra_data)

    def test_identity_request_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001906eab88c888e010000050101000501")
        message = IdentityMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"), message_id=1, code=Eap.REQUEST, identity="")
        packed_message = MessagePacker.pack(message)
        self.assertEqual(expected_packed_message, packed_message)

    def test_identity_response_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001422e9545e888e0100001102000011014a6f686e2e4d63477569726b")
        message = IdentityMessage(src_mac=MacAddress.from_string("00:14:22:e9:54:5e"), message_id=0, code=Eap.RESPONSE, identity="John.McGuirk")
        packed_message = MessagePacker.pack(message)
        self.assertEqual(expected_packed_message, packed_message)

    def test_md5_challenge_request_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001906eab88c888e01000016010100160410824788d693e2adac6ce15641418228cf")
        message = Md5ChallengeMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"), message_id=1, code=Eap.REQUEST, challenge=build_byte_string("824788d693e2adac6ce15641418228cf"), extra_data=b"")
        packed_message = MessagePacker.pack(message)
        self.assertEqual(expected_packed_message, packed_message)

    def test_md5_challenge_response_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001422e9545e888e010000220201002204103a535f0ee8c6b34fe714aa7dad9a0e154a6f686e2e4d63477569726b")
        message = Md5ChallengeMessage(src_mac=MacAddress.from_string("00:14:22:e9:54:5e"), message_id=1, code=Eap.RESPONSE, challenge=build_byte_string("3a535f0ee8c6b34fe714aa7dad9a0e15"), extra_data=b"John.McGuirk")
        packed_message = MessagePacker.pack(message)
        self.assertEqual(expected_packed_message, packed_message)

    def test_eapol_start_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e01010000")
        message = MessageParser.parse(packed_message)
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertTrue(isinstance(message, EapolStartMessage))

    def test_eapol_start_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001906eab88c888e01010000")
        message = EapolStartMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"))
        packed_message = MessagePacker.pack(message)
        self.assertEqual(expected_packed_message, packed_message)

    def test_eapol_logoff_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e01020000")
        message = MessageParser.parse(packed_message)
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertTrue(isinstance(message, EapolLogoffMessage))

    def test_eapol_logoff_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001906eab88c888e01020000")
        message = EapolLogoffMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"))
        packed_message = MessagePacker.pack(message)
        self.assertEqual(expected_packed_message, packed_message)

    def test_success_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e0100000403ff0004")
        message = MessageParser.parse(packed_message)
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertEqual(255, message.message_id)
        self.assertTrue(isinstance(message, SuccessMessage))

    def test_success_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001906eab88c888e0100000403ff0004")
        message = SuccessMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"), message_id=255)
        packed_message = MessagePacker.pack(message)
        self.assertEqual(expected_packed_message, packed_message)

    def test_failure_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e0100000404ff0004")
        message = MessageParser.parse(packed_message)
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertEqual(255, message.message_id)
        self.assertTrue(isinstance(message, FailureMessage))

    def test_failure_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001906eab88c888e0100000404ff0004")
        message = FailureMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"), message_id=255)
        packed_message = MessagePacker.pack(message)
        self.assertEqual(expected_packed_message, packed_message)
