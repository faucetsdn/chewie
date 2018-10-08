
# pylint: disable=line-too-long
# pylint: disable=missing-docstring

import binascii
import ipaddress
import time
import unittest

from netils import build_byte_string, struct

from chewie.message_parser import  SuccessMessage
from chewie.radius import Radius, RadiusAccessAccept, RadiusAttributesList, \
    InvalidResponseAuthenticatorError, RadiusAccessChallenge, RadiusAccessRequest
from chewie.radius_attributes import create_attribute
from chewie.radius_datatypes import Vsa, String, Enum, Text, Integer, Ipv6prefix, Ipv4addr, \
    Ipv6addr, Ipv4prefix, Time


class RadiusTestCase(unittest.TestCase):
    def test_radius_access_request_parses(self):
        packed_message = build_byte_string("010000a3982a0ba06d3557f0dbc8ba6e823822f1010b686f737431757365721e1434342d34342d34342d34342d34342d34343a3d06000000130606000000021f1330302d30302d30302d31312d31312d30314d17434f4e4e45435420304d627073203830322e3131622c12433634383030344139433930353537390c06000005784f100201000e01686f73743175736572501273f82750f6f261a95a7cc7d318b9f573")
        message = Radius.parse(packed_message, secret="SECRET",
                               request_authenticator_callback=lambda x: None)
        self.assertEqual(message.packet_id, 0)
        self.assertEqual(message.authenticator, b"982a0ba06d3557f0dbc8ba6e823822f1")
        msg_attr = message.attributes
        self.assertEqual(len(msg_attr.attributes), 10, msg_attr.attributes)
        self.assertEqual(msg_attr.find('User-Name').data(), 'host1user')
        self.assertEqual(msg_attr.find('Called-Station-Id').data(),
                         "44-44-44-44-44-44:")
        self.assertEqual(msg_attr.find('NAS-Port-Type').data(), 19)
        self.assertEqual(msg_attr.find('Service-Type').data(), 2)
        self.assertEqual(msg_attr.find('Connect-Info').data(),
                         "CONNECT 0Mbps 802.11b")
        self.assertEqual(msg_attr.find('Acct-Session-Id').data(),
                         "C648004A9C905579")
        self.assertEqual(msg_attr.find('Framed-MTU').data(), 1400)
        eap_msg = msg_attr.find('EAP-Message').data()
        self.assertEqual(eap_msg.message_id, 1)
        self.assertEqual(eap_msg.code, 2)
        self.assertEqual(eap_msg.identity, "host1user")

        self.assertEqual(binascii.hexlify(
            msg_attr.find('Message-Authenticator').data()),
                         b"73f82750f6f261a95a7cc7d318b9f573")

    def test_radius_access_accept_parses(self):
        packed_message = build_byte_string("0201004602970aff2ef0700780f70848e90d24101a0f00003039010973747564656e744f06030200045012d7ec84e8864dd6cd00916c1d5a3cf41b010b686f73743175736572")
        message = Radius.parse(packed_message, secret="SECRET",
                               request_authenticator_callback=
                               lambda x: bytes.fromhex("a0b4ace0b367114b1a16d76e2bfed5d8"))
        self.assertEqual(message.packet_id, 1)
        self.assertEqual(message.authenticator, b"02970aff2ef0700780f70848e90d2410")
        msg_attr = message.attributes
        self.assertEqual(len(msg_attr.attributes), 4)
        eap_msg = msg_attr.find('EAP-Message').data()
        self.assertEqual(eap_msg.message_id, 2)
        self.assertIsInstance(eap_msg, SuccessMessage)
        self.assertEqual(binascii.hexlify(msg_attr.find(
            'Message-Authenticator').data()),
                         b"d7ec84e8864dd6cd00916c1d5a3cf41b")
        self.assertEqual(msg_attr.find('User-Name').data(), 'host1user')

    def test_radius_access_accept_packs(self):
        expected_packed_message = build_byte_string("02010046"
                                                    "02970aff2ef0700780f70848e90d2410"
                                                    "1a0f00003039010973747564656e74"
                                                    "4f0603020004"
                                                    "5012d7ec84e8864dd6cd00916c1d5a3cf41b"
                                                    "010b686f73743175736572")
        attr_list = list()
        attr_list.append(create_attribute('Vendor-Specific',
                                          bytes.fromhex("00003039010973747564656e74")))
        attr_list.append(create_attribute('EAP-Message', "03020004"))
        attr_list.append(create_attribute('Message-Authenticator',
                                          bytes.fromhex("d7ec84e8864dd6cd00916c1d5a3cf41b")))
        attr_list.append(create_attribute('User-Name', "host1user"))
        attributes = RadiusAttributesList(attr_list)
        access_accept = RadiusAccessAccept(1, bytes.fromhex("02970aff2ef0700780f70848e90d2410"),
                                           attributes)
        packed_message = access_accept.pack()
        self.assertEqual(len(expected_packed_message), len(packed_message))
        self.assertEqual(expected_packed_message, packed_message)

    def test_corrupted_packets(self):

        # the original response authenticator does not match the computed one
        #  because there is a change in the packet contents
        packed_message = build_byte_string(
            "0b00005056d9280d3e4fed327eb31cf1823f8c244f1801020016041074d3db089b727d9cc5774599e4a32a295012982a0ba06d3557f0dbc8ba6e823822f1181219ddf6d119dff272fa26666666666666")

        self.assertRaises(InvalidResponseAuthenticatorError, Radius.parse,
                          packed_message, secret="SECRET",
                          request_authenticator_callback=
                          lambda x: bytes.fromhex("982a0ba06d3557f0dbc8ba6e823822f1"))

        # the original response authenticator does not match the computed one
        #  because the message authenticator was 'corrupted'
        packed_message = build_byte_string(
            "0b00005056d9280d3e4fed327eb31cf1823f8c244f1801020016041074d3db089b727d9cc5774599e4a32a29501266666666666666666666666666666666181219ddf6d119dff272fa2fe16c34990c7d")

        self.assertRaises(InvalidResponseAuthenticatorError, Radius.parse, packed_message,
                          secret="SECRET",
                          request_authenticator_callback=
                          lambda x: bytes.fromhex("982a0ba06d3557f0dbc8ba6e823822f1"))

        # TODO How can we test that response authenticator is correct
        #  but message authenticator is not?
        #  response authenticator relies on the message authenticator being correct.
        #  unless there is a hashing collision when messageauthenticator is wrong.

    def test_secret_none_fails(self):
        packed_message = build_byte_string(
            "0b00005056d9280d3e4fed327eb31cf1823f8c244f1801020016041074d3db089b727d9cc5774599e4a32a295012ecc840b316217c851bd6708afb554b24181219ddf6d119dff272fa2fe16c34990c7d")

        self.assertRaises(ValueError, Radius.parse, packed_message, secret="",
                          request_authenticator_callback=
                          lambda x: bytes.fromhex("982a0ba06d3557f0dbc8ba6e823822f1"))

    def test_radius_access_challenge_parses(self):
        packed_message = build_byte_string(
            "0b00005056d9280d3e4fed327eb31cf1823f8c244f1801020016041074d3db089b727d9cc5774599e4a32a295012ecc840b316217c851bd6708afb554b24181219ddf6d119dff272fa2fe16c34990c7d")
        message = Radius.parse(packed_message, secret="SECRET",
                               request_authenticator_callback=
                               lambda x: bytes.fromhex("982a0ba06d3557f0dbc8ba6e823822f1"))
        self.assertEqual(message.packet_id, 0)
        self.assertEqual(message.authenticator, b"56d9280d3e4fed327eb31cf1823f8c24")
        msg_attr = message.attributes
        self.assertEqual(len(msg_attr.attributes), 3)
        eap_msg = msg_attr.find('EAP-Message').data()
        self.assertEqual(eap_msg.code, 1)
        self.assertEqual(eap_msg.message_id, 2)
        self.assertEqual(binascii.hexlify(eap_msg.challenge),
                         b"74d3db089b727d9cc5774599e4a32a29")
        self.assertEqual(binascii.hexlify(msg_attr.find(
            'Message-Authenticator').data()),
                         b"ecc840b316217c851bd6708afb554b24")
        self.assertEqual(binascii.hexlify(msg_attr.find('State').data()),
                         b"19ddf6d119dff272fa2fe16c34990c7d")

    def test_radius_access_challenge_ttls_parses(self):
        packed_message = build_byte_string(
            "0b06042c54dbc73332c00c0347fc4b462d1811a74fff016a03ec15c000000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c6520434fff6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c554fff856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f4ff7302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2501226e219fc875fd78976eb2b9b475b14881812c1591073c33305b4fa8bd26dd27eafd9")
        message = Radius.parse(packed_message, secret="SECRET",
                               request_authenticator_callback=
                               lambda x: bytes.fromhex("0d64ffb8bc76d457d337e5f5692534aa"))
        self.assertEqual(message.packet_id, 6)
        self.assertEqual(message.authenticator, b"54dbc73332c00c0347fc4b462d1811a7")
        msg_attr = message.attributes
        self.assertEqual(len(msg_attr.attributes), 3)
        eap_msg = msg_attr.find('EAP-Message').data()
        self.assertEqual(eap_msg.code, 1)
        self.assertEqual(eap_msg.message_id, 106)
        self.assertEqual(eap_msg.flags, 0xc0)
        self.assertEqual(binascii.hexlify(eap_msg.extra_data), b"00000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c652043"
                         b"6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c55"
                         b"856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f"
                         b"302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2")
        self.assertEqual(binascii.hexlify(msg_attr.find(
            'Message-Authenticator').data()),
                         b"26e219fc875fd78976eb2b9b475b1488")
        self.assertEqual(binascii.hexlify(msg_attr.find('State').data()),
                         b"c1591073c33305b4fa8bd26dd27eafd9")

    def test_radius_access_challenge_packs(self):
        expected_packed_message = build_byte_string("0b06042c"
                                                    "54dbc73332c00c0347fc4b462d1811a74fff016a03ec15c000000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c6520434fff6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c554fff856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f4ff7302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2"
                                                    "501226e219fc875fd78976eb2b9b475b1488"
                                                    "1812c1591073c33305b4fa8bd26dd27eafd9")
        attr_list = list()
        attr_list.append(create_attribute('EAP-Message',
                                          "016a03ec15c000000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c652043"))
        attr_list.append(create_attribute('EAP-Message',
                                          "6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c55"))
        attr_list.append(create_attribute('EAP-Message',
                                          "856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f"))
        attr_list.append(create_attribute('EAP-Message',
                                          "302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2"))
        attr_list.append(create_attribute('Message-Authenticator',
                                          bytes.fromhex("26e219fc875fd78976eb2b9b475b1488")))
        attr_list.append(create_attribute('State',
                                          bytes.fromhex("c1591073c33305b4fa8bd26dd27eafd9")))
        attributes = RadiusAttributesList(attr_list)
        access_challenge = RadiusAccessChallenge(6,
                                                 bytes.fromhex("54dbc73332c00c0347fc4b462d1811a7"),
                                                 attributes)
        packed_message = access_challenge.pack()
        self.assertEqual(len(expected_packed_message), len(packed_message))
        self.assertEqual(expected_packed_message, packed_message)

    def test_radius_access_challenge_packs2(self):
        expected_packed_message = build_byte_string("0b06042c"
                                                    "54dbc73332c00c0347fc4b462d1811a74fff016a03ec15c000000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c6520434fff6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c554fff856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f4ff7302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2"
                                                    "501226e219fc875fd78976eb2b9b475b1488"
                                                    "1812c1591073c33305b4fa8bd26dd27eafd9")
        attr_list = list()
        attr_list.append(create_attribute('EAP-Message',
            "016a03ec15c000000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c652043"
            "6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c55"
            "856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f"
            "302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2"))
        attr_list.append(create_attribute('Message-Authenticator',
                                          bytes.fromhex("26e219fc875fd78976eb2b9b475b1488")))
        attr_list.append(create_attribute('State',
                                          bytes.fromhex("c1591073c33305b4fa8bd26dd27eafd9")))
        attributes = RadiusAttributesList(attr_list)
        access_challenge = RadiusAccessChallenge(6,
                                                 bytes.fromhex("54dbc73332c00c0347fc4b462d1811a7"),
                                                 attributes)
        packed_message = access_challenge.pack()
        self.assertEqual(len(expected_packed_message), len(packed_message))
        self.assertEqual(expected_packed_message, packed_message)

    def test_radius_access_request_packs(self):
        expected_packed_message = build_byte_string("010e01dc688d6504db3c757243f995d5f0d32e50010b686f737431757365721e1434342d34342d34342d34342d34342d34343a3d06000000130606000000021f1330302d30302d30302d31312d31312d30314d17434f4e4e45435420304d627073203830322e3131622c12433634383030344139433930353537390c06000005784fff02250133150016030101280100012403032c36dbf8ee16b94b28efdb8c5603e07823f9b716557b5ef2624b026daea115760000aac030c02cc028c024c014c00a00a500a300a1009f006b006a0069006800390038003700360088008700860085c032c02ec02ac026c00fc005009d003d00350084c02fc02bc027c023c013c00900a400a200a0009e00670040003f003e0033003200310030009a0099009800970045004400430042c031c02dc029c025c00ec004009c003c002f00960041c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff01000051000b000403000102000a001c001a00170019001c001b0018001a004f3816000e000d000b000c0009000a000d0020001e060106020603050105020503040104020403030103020303020102020203000f0001011812cefe6083cfdb75dd64722c274ec353725012ab67ed568931f12d258f9ffda931159e")

        attr_list = list()
        attr_list.append(create_attribute('User-Name', "host1user"))
        attr_list.append(create_attribute('Called-Station-Id', "44-44-44-44-44-44:"))
        attr_list.append(create_attribute('NAS-Port-Type', 0x13))
        attr_list.append(create_attribute('Service-Type', 0x02))
        attr_list.append(create_attribute('Calling-Station-Id', "00-00-00-11-11-01"))
        attr_list.append(create_attribute('Connect-Info', "CONNECT 0Mbps 802.11b"))
        attr_list.append(create_attribute('Acct-Session-Id', "C648004A9C905579"))
        attr_list.append(create_attribute('Framed-MTU', 0x0578))

        attr_list.append(create_attribute('EAP-Message',
            "02250133150016030101280100012403032c36dbf8ee16b94b28efdb8c5603e07823f9b716557b5ef2624b026daea115760000aac030c02cc028c024c014c00a00a500a300a1009f006b006a0069006800390038003700360088008700860085c032c02ec02ac026c00fc005009d003d00350084c02fc02bc027c023c013c00900a400a200a0009e00670040003f003e0033003200310030009a0099009800970045004400430042c031c02dc029c025c00ec004009c003c002f00960041c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff01000051000b000403000102000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101"))
        attr_list.append(create_attribute('State',
                                          bytes.fromhex("cefe6083cfdb75dd64722c274ec35372")))
        attr_list.append(create_attribute('Message-Authenticator',
                                          bytes.fromhex("00000000000000000000000000000000")))

        attributes = RadiusAttributesList(attr_list)
        access_request = RadiusAccessRequest(14, bytes.fromhex("688d6504db3c757243f995d5f0d32e50"),
                                             attributes)
        packed_message = access_request.build("SECRET")

        self.assertEqual(len(expected_packed_message), len(packed_message))
        self.assertEqual(expected_packed_message, packed_message)

    def test_parse_illegal_radius_datatype_lengths(self):

        self.assertRaises(ValueError, Integer.parse, (1500).to_bytes(3, byteorder='big'), 5)
        self.assertRaises(ValueError, Integer.parse, bytes.fromhex("01234567890123456789"), 5)

        self.assertRaises(ValueError, Enum.parse, bytes.fromhex("000002"), 7)
        self.assertRaises(ValueError, Enum.parse, bytes.fromhex("01234567890123456789"), 7)

        self.assertRaises(ValueError, Text.parse, "".encode(), 1)
        self.assertRaises(ValueError, Text.parse,
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName".encode(), 1)

        self.assertRaises(ValueError, String.parse, "".encode(), 24)
        self.assertRaises(ValueError, String.parse, "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260Char".encode(), 24)

        self.assertRaises(ValueError, Vsa.parse, "abcd".encode(), 26)
        self.assertRaises(ValueError, Vsa.parse,
                          "270CharacterLengthVSAAttribute270CharacterLengthVSAAttribute"
                          "270CharacterLengthVSAAttribute270CharacterLengthVSAAttribute"
                          "270CharacterLengthVSAAttribute270CharacterLengthVSAAttribute"
                          "270CharacterLengthVSAAttribute270CharacterLengthVSAAttribute"
                          "270CharacterLen270CharacterLen".encode(), 26)
        # Cannot test Concat datatype, it does not check length

    def test_pack_illegal_radius_datatype_lengths(self):
        self.assertRaises(ValueError, create_attribute, 'Framed-MTU', -1)
        self.assertRaises(ValueError, create_attribute,'Framed-MTU', 10000000000)

        self.assertRaises(ValueError, create_attribute,'Service-Type', -1)
        self.assertRaises(ValueError, create_attribute,'Service-Type', 10000000000)

        self.assertRaises(ValueError, create_attribute,'User-Name', "")
        self.assertRaises(ValueError, create_attribute,'User-Name',
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName")

        self.assertRaises(ValueError, create_attribute,'State', "")
        self.assertRaises(ValueError, create_attribute,'State',
                          "260CharacterLengthState260CharacterLengthState"
                          "260CharacterLengthState260CharacterLengthState"
                          "260CharacterLengthState260CharacterLengthState"
                          "260CharacterLengthState260CharacterLengthState"
                          "260CharacterLengthState260CharacterLengthState"
                          "260CharacterLengthState260Char")

        # Cannot test Concat datatype, it does not check length
        # Cannot test VSA datatype, Nothing is using it at the moment.

    def test_radius_extract_attributes(self):

        # This list of radius AVP, contains multiple VSA attributes.
        attributes = []
        attributes_data = build_byte_string("1a3a000001371134904a76cd1ffff59a3e1365e09441c41d83454aedafc1d9099d32ade23714a4d2c0898ff23997c89f59f1149bcb709fb889dc1a3a0000013710349e92efe66d278d977e3fe87faa650b391c43103d3d8e662bb3881807f1b3313ed975d3cfa85d45a6f3b83f6b98364a99135e4f06032a0004501256aef88d10224c30e6b3563acf963758010b686f73743175736572")
        attributes_to_concat = {}
        RadiusAttributesList.extract_attributes(attributes_data, attributes, attributes_to_concat)
        self.assertEqual(len(attributes), 5)
        self.assertEqual(len(attributes_to_concat), 1)
        self.assertEqual(list(attributes_to_concat.values())[0][0][1], 2)
        # check that the concated EAPMessage is marked position 2

        # This list of radius AVP contains multiple EAPMessages.
        attributes = []
        attributes_data = build_byte_string("4fff012802bc158000000a76130101ff040530030101ff30360603551d1f042f302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e6f72672f6578616d706c655f63612e63726c300d06092a864886f70d01010b05000382010100139e9c2b1e9bf30c6567759ffb57af9f031a59b6a8adb1702a55de2e51f2286715ef1399ebdc593d38db3ad4794c3e78037d3de5612cba33cefc5b830c3a2118bfc0572d201c07105b7c0ef5bb64225d959afef6a4527a88d1e5fd552fd16775a5c90802d11ad793da157441f7a181f85a2908ebcb87a86960c6d3ae631019bc73f850bc5be494a97084ccaea1cc13c44a4fdf0ef123c067b688e47a4fff4d223c15fd56798051ff4912c721f15c96061ef683b1ade02b5449b06184f59d4218f2287d35cfa0a3a4f65e40c8750d0c70dc00d65a8981e0a2cf6961b1355c10d399ce583a426e211b0feef37da67a57bbbc81d912d5379668cfdc3666bacf5e9d9c7d160303014d0c0001490300174104b275c284c5c067b9c3104305ba6704b4b0e083f0e285d9b205a8d7307e503907478f314679d084a0f1ccbc3ceaa6b6d56c588654d223fd16514bba463c5f8d7006010100bca760ef9aab5f1cf9239bab7d0bbf585e12f9c6440b9dd36affc87ff8f334b0dbea94686edbcff9143bd40a5136b065d5599742665fa27d5ec5e86898b7c8cc2c375d190646c64fc444df7911f41a12a7219f667527cfc4ba99b684fb763a01f4dc361a891906e3ade0c6e787c096f868726a5aafafb76ce71ce896b50015c9db89e9c3d13c90e90b5d82a1327941404298c1e358cbc7bbbf8e4fe2e1ecafbcbddfbe0b1a7d3f0769306f16f3ed4972b14b8af0f51761053754ec73a1a41b294fe0d00a9281e3d9c0175651d2bbaf28df32a25bfbae85983a3935891f0a955b636b3540cde3aba4ec20d62988a81a608b450e87b3eefcb66f50cf3104a4b367122d16030300040e00000050125f3ac1f2c8e65dab1bf90b9604cd65aa1812cefe6083cad675dd64722c274ec35372")
        attributes_to_concat = {}
        RadiusAttributesList.extract_attributes(attributes_data, attributes, attributes_to_concat)
        self.assertEqual(len(attributes), 5)
        self.assertEqual(len(attributes_to_concat), 1)
        # check that the concated EAPMessage is marked position 0
        self.assertEqual(list(attributes_to_concat.values())[0][0][1], 0)

    def test_ipv6prefix_datatype(self):

        parsed = Ipv6prefix.parse(build_byte_string("0080ffffffffffffffffffffffffffffffff"), 97)

        self.assertEqual(parsed.pack()[2:],
                         build_byte_string("0080ffffffffffffffffffffffffffffffff"))

        parsed = Ipv6prefix.parse(build_byte_string("0070ffffffffffffffffffffffffffff0000"), 97)

        self.assertEqual(parsed.pack()[2:],
                         build_byte_string("0070ffffffffffffffffffffffffffff0000"))

        parsed = Ipv6prefix.parse(build_byte_string("007cfffffffffffffffffffffffffffffff0"), 97)
        self.assertEqual(parsed.pack()[2:],
                         build_byte_string("007cfffffffffffffffffffffffffffffff0"))

        self.assertRaises(ValueError, Ipv6prefix.parse,
                          build_byte_string("007cffffffffffffffffffffffffffffffff"), 97)
        self.assertRaises(ValueError, Ipv6prefix.parse,
                          build_byte_string("007cfffffffffffffffffffffffffffffff6"), 97)

        parsed = Ipv6prefix.parse(build_byte_string("0048ffffffffffffffffff"), 97)
        self.assertEqual(parsed.pack()[2:],
                         build_byte_string("0048ffffffffffffffffff"))

        parsed = Ipv6prefix.parse(build_byte_string("0045fffffffffffffffff8"), 97)
        self.assertEqual(parsed.pack()[2:],
                         build_byte_string("0045fffffffffffffffff8"))

        # bits outside prefix length are 1
        self.assertRaises(ValueError, Ipv6prefix.parse,
                          build_byte_string("0040fffffffffffffffff8"), 97)

        # reserved is not 0
        self.assertRaises(ValueError, Ipv6prefix.parse,
                          build_byte_string("507cfffffffffffffffffffffffffffffff0"), 97)

        # prefix length > 128
        self.assertRaises(ValueError, Ipv6prefix.parse,
                          build_byte_string("00fcfffffffffffffffffffffffffffffff0"), 97)

        create_attribute("Framed-IPv6-Prefix",
                         bytes_data=build_byte_string("0045fffffffffffffffff8"))
        create_attribute("Framed-IPv6-Prefix",
                         bytes_data=build_byte_string("007cfffffffffffffffffffffffffffffff0"))
        create_attribute("Framed-IPv6-Prefix",
                         bytes_data=build_byte_string("0070ffffffffffffffffffffffffffff0000"))

    def test_ipv4prefix_datatype(self):
        parsed = Ipv4prefix.parse(build_byte_string("0020ffffffff"), 155)
        self.assertEqual(parsed.pack()[2:],
                         build_byte_string("0020ffffffff"))

        parsed = Ipv4prefix.parse(build_byte_string("0018ffffff00"), 155)
        self.assertEqual(parsed.pack()[2:],
                         build_byte_string("0018ffffff00"))

        # prefix length is too long
        self.assertRaises(ValueError, Ipv4prefix.parse, build_byte_string("0021ffffff00"), 155)

        # bits outside length are 1
        self.assertRaises(ValueError, Ipv4prefix.parse, build_byte_string("0005ffffff00"), 155)

        # Reserverd is not 0
        self.assertRaises(ValueError, Ipv4prefix.parse, build_byte_string("0518ffffff00"), 155)

        ipv4_prefix = create_attribute("PMIP6-Home-IPv4-HoA",
                                       bytes_data=build_byte_string("0020ffffffff"))
        self.assertEqual(ipv4_prefix.data(), build_byte_string("0020ffffffff"))

    def test_ipv4addr_datatype(self):
        parsed = Ipv4addr.parse(ipaddress.v4_int_to_packed(
            int(ipaddress.IPv4Address("192.168.1.50"))),
                                4)

        self.assertEqual(parsed.pack()[2:],
                         ipaddress.v4_int_to_packed(
                             int(ipaddress.IPv4Address("192.168.1.50")))
                         )

        parsed = Ipv4addr.parse(ipaddress.v4_int_to_packed(
            int(ipaddress.IPv4Address("255.255.255.255"))),
                                4)

        self.assertEqual(parsed.pack()[2:],
                         ipaddress.v4_int_to_packed(
                             int(ipaddress.IPv4Address("255.255.255.255")))
                         )

        ipv4 = create_attribute("NAS-IP-Address", raw_data="255.255.225.0")
        self.assertEqual(ipv4.data(), "255.255.225.0")

        ipv4 = create_attribute("NAS-IP-Address", raw_data="1.0.1.254")
        self.assertEqual(ipv4.data(), "1.0.1.254")

        self.assertRaises(ipaddress.AddressValueError, create_attribute, "NAS-IP-Address",
                          raw_data="260.260.260.1")
        self.assertRaises(ipaddress.AddressValueError, create_attribute, "NAS-IP-Address",
                          raw_data="260.260.260.1")

    def test_ipv6addr_datatype(self):

        parsed = Ipv6addr.parse(ipaddress.v6_int_to_packed(
            int(ipaddress.IPv6Address("1234:5678:90ab:cdef:fedc:ba09:8765:4321"))),
                                95)

        self.assertEqual(parsed.pack()[2:],
                         ipaddress.v6_int_to_packed(
                             int(ipaddress.IPv6Address("1234:5678:90ab:cdef:fedc:ba09:8765:4321")))
                         )

        parsed = Ipv6addr.parse(ipaddress.v6_int_to_packed(
            int(ipaddress.IPv6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))),
                                95)

        self.assertEqual(parsed.pack()[2:],
                         ipaddress.v6_int_to_packed(
                             int(ipaddress.IPv6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")))
                         )

        ipv6 = create_attribute("NAS-IPv6-Address",
                                raw_data="ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
        self.assertEqual(ipv6.data(), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")

        ipv6 = create_attribute("NAS-IPv6-Address",
                                raw_data="FE80:0::AB8")
        self.assertEqual(ipv6.data(), "fe80::ab8")

        self.assertRaises(ipaddress.AddressValueError, create_attribute, "NAS-IPv6-Address",
                          raw_data="ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff::fail")
        self.assertRaises(ipaddress.AddressValueError, create_attribute, "NAS-IPv6-Address",
                          raw_data="this:is:not::ipv6")

    def test_time_datatype(self):
        current_time = time.time()
        t = create_attribute("Event-Timestamp", current_time)
        # time.time() returns a float which in python is actually a double.
        #  but the Time type only uses single precision.
        # So here we convert the double precision to single.
        current_time_single_precision = struct.unpack("!f", struct.pack("!f", current_time))[0]

        self.assertEqual(t.data(), current_time_single_precision)

        parsed = Time.parse(t.bytes_data, 55)
        self.assertEqual(parsed.pack()[2:], struct.pack('!f', current_time))
