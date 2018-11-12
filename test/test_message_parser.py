
# pylint: disable=missing-docstring

import unittest
from netils import build_byte_string
from chewie.message_parser import MessageParser, MessagePacker, IdentityMessage, \
    EapolStartMessage, EapolLogoffMessage, SuccessMessage, FailureMessage, GenericMessage
from chewie.mac_address import MacAddress
from chewie.eap import Eap
from chewie.radius_attributes import State, CalledStationId, NASPortType


class MessageParserTestCase(unittest.TestCase):
    def test_identity_request_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e010000050101000501000000")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertEqual(1, message.message_id)
        self.assertEqual(Eap.REQUEST, message.code)
        self.assertEqual("", message.identity)

    def test_identity_response_message_parses(self):
        packed_message = build_byte_string(
            "0180c2000003001422e9545e888e0100001102000011014a6f686e2e4d63477569726b")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:14:22:e9:54:5e"), message.src_mac)
        self.assertEqual(0, message.message_id)
        self.assertEqual(Eap.RESPONSE, message.code)
        self.assertEqual("John.McGuirk", message.identity)

    def test_md5_challenge_request_message_parses(self):
        packed_message = build_byte_string(
            "0180c2000003001906eab88c888e01000016010100160410824788d693e2adac6ce15641418228cf0000")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertEqual(1, message.message_id)
        self.assertEqual(Eap.REQUEST, message.code)
        self.assertEqual(build_byte_string("10824788d693e2adac6ce15641418228cf"),
                         message.extra_data)

    def test_md5_challenge_response_message_parses(self):
        packed_message = build_byte_string(
            "0180c2000003001422e9545e888e010000220201002204103a535f0ee8c6b34fe714aa7dad9a0e154a6f686e2e4d63477569726b")  # pylint: disable=line-too-long
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:14:22:e9:54:5e"), message.src_mac)
        self.assertEqual(1, message.message_id)
        self.assertEqual(Eap.RESPONSE, message.code)
        self.assertEqual(build_byte_string("10") +
                         build_byte_string("3a535f0ee8c6b34fe714aa7dad9a0e15") +
                         b"John.McGuirk",
                         message.extra_data)

    def test_identity_request_message_packs(self):
        expected_packed_message = build_byte_string(
            "0180c2000003001906eab88c888e010000050101000501")
        message = IdentityMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"), message_id=1,
                                  code=Eap.REQUEST, identity="")
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:19:06:ea:b8:8c"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_identity_response_message_packs(self):
        expected_packed_message = build_byte_string(
            "0180c2000003001422e9545e888e0100001102000011014a6f686e2e4d63477569726b")
        message = IdentityMessage(src_mac=MacAddress.from_string("00:14:22:e9:54:5e"),
                                  message_id=0, code=Eap.RESPONSE, identity="John.McGuirk")
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:14:22:e9:54:5e"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_md5_challenge_request_message_packs(self):
        expected_packed_message = build_byte_string(
            "0180c2000003001906eab88c888e01000016010100160410824788d693e2adac6ce15641418228cf")
        message = GenericMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"),
                                 message_id=1,
                                 code=Eap.REQUEST,
                                 packet_type=Eap.MD5_CHALLENGE,
                                 extra_data=build_byte_string(
                                          "10824788d693e2adac6ce15641418228cf"))
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:19:06:ea:b8:8c"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_md5_challenge_response_message_packs(self):
        expected_packed_message = build_byte_string(
            "0180c2000003001422e9545e888e010000220201002204103a535f0ee8c6b34fe714aa7dad9a0e154a6f686e2e4d63477569726b")  # pylint: disable=line-too-long
        message = GenericMessage(src_mac=MacAddress.from_string("00:14:22:e9:54:5e"),
                                 message_id=1,
                                 code=Eap.RESPONSE,
                                 packet_type=Eap.MD5_CHALLENGE,
                                 extra_data=
                                 build_byte_string(
                                     "103a535f0ee8c6b34fe714aa7dad9a0e15") +
                                            b"John.McGuirk")
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:14:22:e9:54:5e"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_eapol_start_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e01010000")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertTrue(isinstance(message, EapolStartMessage))

    def test_eapol_start_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001906eab88c888e01010000")
        message = EapolStartMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"))
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:19:06:ea:b8:8c"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_eapol_logoff_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e01020000")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertTrue(isinstance(message, EapolLogoffMessage))

    def test_eapol_logoff_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001906eab88c888e01020000")
        message = EapolLogoffMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"))
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:19:06:ea:b8:8c"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_success_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e0100000403ff0004")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertEqual(255, message.message_id)
        self.assertTrue(isinstance(message, SuccessMessage))

    def test_success_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001906eab88c888e0100000403ff0004")
        message = SuccessMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"),
                                 message_id=255)
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:19:06:ea:b8:8c"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_failure_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e0100000404ff0004")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertEqual(255, message.message_id)
        self.assertTrue(isinstance(message, FailureMessage))

    def test_failure_message_packs(self):
        expected_packed_message = build_byte_string("000000000001001906eab88c888e0100000404ff0004")
        message = FailureMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"),
                                 message_id=255)
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:19:06:ea:b8:8c"),
                                                     MacAddress.from_string("00:00:00:00:00:01"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_ttls_message_parses(self):
        packed_message = build_byte_string("000000111101444444444444888e"
                                           "01000006016900061520")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("44:44:44:44:44:44"), message.src_mac)
        self.assertEqual(105, message.message_id)
        self.assertIsInstance(message, GenericMessage)
        self.assertEqual(message.packet_type, Eap.TTLS)

    def test_ttls_message_packs(self):
        expected_packed_message = build_byte_string("000000111101444444444444888e"
                                                    "01000006016900061520")
        message = GenericMessage(src_mac=MacAddress.from_string("44:44:44:44:44:44"),
                                 message_id=105, code=Eap.REQUEST,
                                 packet_type=Eap.TTLS,
                                 extra_data=0x20.to_bytes(1, 'big'))
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("44:44:44:44:44:44"),
                                                     MacAddress.from_string("00:00:00:11:11:01"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_tls_message_parses(self):
        packed_message = build_byte_string("000000111101444444444444888e"
                                           "010000b2026900b20d0016030100a7010000a303038c8007fa4ffe8f11fbe62debce4a1385e70be51efe77b105d205d2dc9ae815a5000038c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff01000042000b000403000102000a000a0008001d0017001900180016000000170000000d0020001e060106020603050105020503040104020403030103020303020102020203")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("44:44:44:44:44:44"), message.src_mac)
        self.assertEqual(105, message.message_id)
        # self.assertEqual(0, message.flags)
        self.assertIsInstance(message, GenericMessage)

    def test_tls_message_packs(self):
        expected_packed_message = build_byte_string("000000111101444444444444888e"
                                                    "010000b2026900b20d0016030100a7010000a303038c8007fa4ffe8f11fbe62debce4a1385e70be51efe77b105d205d2dc9ae815a5000038c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff01000042000b000403000102000a000a0008001d0017001900180016000000170000000d0020001e060106020603050105020503040104020403030103020303020102020203")
        message = GenericMessage(src_mac=MacAddress.from_string("44:44:44:44:44:44"),
                              message_id=105, code=Eap.RESPONSE,
                              extra_data=build_byte_string('0016030100a7010000a303038c8007fa4ffe8f11fbe62debce4a1385e70be51efe77b105d205d2dc9ae815a5000038c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff01000042000b000403000102000a000a0008001d0017001900180016000000170000000d0020001e060106020603050105020503040104020403030103020303020102020203'))
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("44:44:44:44:44:44"),
                                                     MacAddress.from_string("00:00:00:11:11:01"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_legacy_nak_message_parses(self):
        packed_message = build_byte_string("0180c2000003000000111101888e"
                                           "01000006026800060315")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:00:00:11:11:01"), message.src_mac)
        self.assertEqual(104, message.message_id)
        self.assertIsInstance(message, GenericMessage)
        self.assertEqual(message.packet_type, Eap.LEGACY_NAK)

    def test_legacy_nak_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003000000111101888e"
                                                    "01000006026800060315")
        message = GenericMessage(src_mac=MacAddress.from_string("00:00:00:11:11:01"),
                                 message_id=104,
                                 code=Eap.RESPONSE,
                                 packet_type=Eap.LEGACY_NAK,
                                 extra_data=(21).to_bytes(length=1, byteorder='big'))
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:00:00:11:11:01"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_radius_packs(self):

        packed_message = build_byte_string("010a0073"
                                           "be5df1f3b3366c69b977e56a7da47cba"
                                           "010675736572"
                                           "1f1330323a34323a61633a31373a30303a3666"
                                           "1e1434342d34342d34342d34342d34342d34343a"
                                           "3d060000000f"
                                           "4f08027100061500"
                                           "1812f51d90b0f76c85835ed4ac882e522748501201531ea8051d136941fece17473f6b4a")  # pylint: disable=line-too-long

        src_mac = MacAddress.from_string("02:42:ac:17:00:6f")
        username = "user"
        radius_packet_id = 10
        request_authenticator = bytes.fromhex("be5df1f3b3366c69b977e56a7da47cba")
        state = State.create(bytes.fromhex("f51d90b0f76c85835ed4ac882e522748"))
        secret = "SECRET"
        extra_attributes = []
        extra_attributes.append(CalledStationId.create('44-44-44-44-44-44:'))
        extra_attributes.append(NASPortType.create(15))

        eap_message = GenericMessage(src_mac, 113, Eap.RESPONSE, Eap.TTLS, 0x0.to_bytes(1, 'big'))

        packed_radius = MessagePacker.radius_pack(eap_message, src_mac, username, radius_packet_id,
                                                  request_authenticator, state, secret,
                                                  extra_attributes)

        self.assertEqual(packed_message, packed_radius)

    def _test_fuzzer_find(self):
        MessageParser.radius_parse(b"0b0a042c0862e7587ec0a4992fa3dca7d978f4dd4fff016a03ec0dc000000b331603030039020000350303d73770f68513cebb2af9fbffe401147b1697a8b674fefdcdcd801cfd08dd53dc00c03000000dff01000100000b00040300010216030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c65204365727469664fff696361746520417574686f72697479301e170d3138313130343233323532365a170d3234303432363233323532365a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100d3a4027c09d269f84646dae141992fe5d0565f2cab16992ffa24fd439e2fbde727d70d73862b0ce0cd0641056281004fffdb2220663f493d19b430fdc7abddc7b6b2c9f8712c900f5769abefd1d9aefb16e2495418f8c77b0529d8b7b99dc9657035685081482583029e4a95d663851e85b43391829a45489dd0e46e6faa599abc4d735a300f95cb8bfb76d5046643a50f84d64cc05154bf24fe6ecabcddc7b0b71148f8d7baeb3f17edc39e595931fcb6a45752d7b79b616d8a881f49e31d754cf6cb5fbc470122a416f8a40d62746fcedd5fa2b6bde0971eaff08e5f4f71cbce0dec138b98bb8690c4f65913583b44b281b5cbb1deb4db328b7d26fe54660214330203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f302d302ba04ff729a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b05000382010100967d49862a2159f4334c01b11d96d70454ae5b0dce10ef7ef9f8411dc00aaaa0fe41173678ca07d685523fb1ec5244067ff80824074e23a6d305b091c544a8eec36d806b61c8124dbdfd709592296b3427f3af9e2009bea93de176cb5d56f39bc3b263dcf1513c6676d1caa17db91acd9a117905e8956385498cba1d221165944d68646d24427c30c561c13160f91400254ded9623720a85a708c156c438e262ecbdcce00b23da9917fed3935d511a36ed9d9b8eafbbf15012fb1514adb33b69b6c8f7320cf937a6ba1A12adac",
                                   "SECRET", lambda x: None)
        MessageParser.ethernet_parse(b'45c1')

        MessageParser.ethernet_parse(b'ffff')
        MessageParser.ethernet_parse(b'000427e29fa6080027fc6ac90800450001c4b5d0007a4001bcea0201010202010101c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e9f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666d4e4f505768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454644d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70717273747576779')