
# pylint: disable=line-too-long
# pylint: disable=missing-docstring

import binascii
import unittest
from collections import namedtuple

from chewie.message_parser import SuccessMessage
from chewie.radius import Radius, RadiusAccessAccept, RadiusAttributesList, \
    InvalidResponseAuthenticatorError, RadiusAccessChallenge, RadiusAccessRequest
from chewie.radius_attributes import UserName, ServiceType, FramedMTU, CalledStationId,\
    AcctSessionId, NASPortType, ConnectInfo, EAPMessage, MessageAuthenticator, State,\
    VendorSpecific, CallingStationId
from chewie.radius_datatypes import Vsa, String, Enum, Text, Integer, Concat
from chewie.utils import MessageParseError


class RadiusTestCase(unittest.TestCase):
    def test_radius_access_request_parses(self):
        packed_message = bytes.fromhex("010000a3982a0ba06d3557f0dbc8ba6e823822f1010b686f737431757365721e1434342d34342d34342d34342d34342d34343a3d06000000130606000000021f1330302d30302d30302d31312d31312d30314d17434f4e4e45435420304d627073203830322e3131622c12433634383030344139433930353537390c06000005784f100201000e01686f73743175736572501273f82750f6f261a95a7cc7d318b9f573")
        # this needs to change - missing key raises a key error, it doesn't return None
        message = Radius.parse(packed_message, secret="SECRET",
                               radius_lifecycle=namedtuple('RadiusLifecycle', 'packet_id_to_request_authenticator')({0: None}))
        self.assertEqual(message.packet_id, 0)
        self.assertEqual(binascii.hexlify(message.authenticator), b"982a0ba06d3557f0dbc8ba6e823822f1")
        msg_attr = message.attributes
        self.assertEqual(len(msg_attr.attributes), 10)
        self.assertEqual(msg_attr.find(UserName.DESCRIPTION).data_type.data(), 'host1user')
        self.assertEqual(msg_attr.find(CalledStationId.DESCRIPTION).data_type.data(),
                         "44-44-44-44-44-44:")
        self.assertEqual(msg_attr.find(NASPortType.DESCRIPTION).data_type.data(), 19)
        self.assertEqual(msg_attr.find(ServiceType.DESCRIPTION).data_type.data(), 2)
        self.assertEqual(msg_attr.find(ConnectInfo.DESCRIPTION).data_type.data(),
                         "CONNECT 0Mbps 802.11b")
        self.assertEqual(msg_attr.find(AcctSessionId.DESCRIPTION).data_type.data(),
                         "C648004A9C905579")
        self.assertEqual(msg_attr.find(FramedMTU.DESCRIPTION).data_type.data(), 1400)
        eap_msg = msg_attr.find(EAPMessage.DESCRIPTION).data_type.data()
        self.assertEqual(eap_msg.message_id, 1)
        self.assertEqual(eap_msg.code, 2)
        self.assertEqual(eap_msg.identity, "host1user")

        self.assertEqual(binascii.hexlify(
            msg_attr.find(MessageAuthenticator.DESCRIPTION).data_type.data()),
                         b"73f82750f6f261a95a7cc7d318b9f573")

    def test_radius_access_accept_parses(self):
        packed_message = bytes.fromhex("0201004602970aff2ef0700780f70848e90d24101a0f00003039010973747564656e744f06030200045012d7ec84e8864dd6cd00916c1d5a3cf41b010b686f73743175736572")
        message = Radius.parse(packed_message, secret="SECRET",
                               radius_lifecycle=namedtuple('RadiusLifecycle', 'packet_id_to_request_authenticator')({
                                 1: bytes.fromhex("a0b4ace0b367114b1a16d76e2bfed5d8")
                               }))
        self.assertEqual(message.packet_id, 1)
        self.assertEqual(binascii.hexlify(message.authenticator), b"02970aff2ef0700780f70848e90d2410")
        msg_attr = message.attributes
        self.assertEqual(len(msg_attr.attributes), 4)
        eap_msg = msg_attr.find(EAPMessage.DESCRIPTION).data_type.data()
        self.assertEqual(eap_msg.message_id, 2)
        self.assertIsInstance(eap_msg, SuccessMessage)
        self.assertEqual(binascii.hexlify(msg_attr.find(
            MessageAuthenticator.DESCRIPTION).data_type.data()),
                         b"d7ec84e8864dd6cd00916c1d5a3cf41b")
        self.assertEqual(msg_attr.find(UserName.DESCRIPTION).data_type.data(), 'host1user')

    def test_radius_access_accept_packs(self):
        expected_packed_message = bytes.fromhex("02010046"
                                                "02970aff2ef0700780f70848e90d2410"
                                                "1a0f00003039010973747564656e74"
                                                "4f0603020004"
                                                "5012d7ec84e8864dd6cd00916c1d5a3cf41b"
                                                "010b686f73743175736572")
        attr_list = list()
        attr_list.append(VendorSpecific.create(bytes.fromhex("00003039010973747564656e74")))
        attr_list.append(EAPMessage.create("03020004"))
        attr_list.append(MessageAuthenticator.create(
            bytes.fromhex("d7ec84e8864dd6cd00916c1d5a3cf41b")))
        attr_list.append(UserName.create("host1user"))
        attributes = RadiusAttributesList(attr_list)
        access_accept = RadiusAccessAccept(1, bytes.fromhex("02970aff2ef0700780f70848e90d2410"),
                                           attributes)
        packed_message = access_accept.pack()
        self.assertEqual(len(expected_packed_message), len(packed_message))
        self.assertEqual(expected_packed_message, packed_message)

    def test_corrupted_packets(self):

        # the original response authenticator does not match the computed one
        #  because there is a change in the packet contents
        packed_message = bytes.fromhex(
            "0b00005056d9280d3e4fed327eb31cf1823f8c244f1801020016041074d3db089b727d9cc5774599e4a32a295012982a0ba06d3557f0dbc8ba6e823822f1181219ddf6d119dff272fa26666666666666")

        try:
            Radius.parse(packed_message, secret="SECRET",
                          radius_lifecycle=namedtuple('RadiusLifecycle', 'packet_id_to_request_authenticator')({
                            0: bytes.fromhex("982a0ba06d3557f0dbc8ba6e823822f1")
                          }))
            self.fail()
        except MessageParseError as exception:
            self.assertIsInstance(exception.__cause__, InvalidResponseAuthenticatorError)

        # the original response authenticator does not match the computed one
        #  because the message authenticator was 'corrupted'
        packed_message = bytes.fromhex(
            "0b00005056d9280d3e4fed327eb31cf1823f8c244f1801020016041074d3db089b727d9cc5774599e4a32a29501266666666666666666666666666666666181219ddf6d119dff272fa2fe16c34990c7d")

        try:
            Radius.parse(packed_message,
                          secret="SECRET",
                          radius_lifecycle=namedtuple('RadiusLifecycle', 'packet_id_to_request_authenticator')({
                            0: bytes.fromhex("982a0ba06d3557f0dbc8ba6e823822f1")
                          }))
            self.fail()
        except MessageParseError as exception:
            self.assertIsInstance(exception.__cause__, InvalidResponseAuthenticatorError)

        # TODO How can we test that response authenticator is correct
        #  but message authenticator is not?
        #  response authenticator relies on the message authenticator being correct.
        #  unless there is a hashing collision when messageauthenticator is wrong.

    def test_secret_none_fails(self):
        packed_message = bytes.fromhex(
            "0b00005056d9280d3e4fed327eb31cf1823f8c244f1801020016041074d3db089b727d9cc5774599e4a32a295012ecc840b316217c851bd6708afb554b24181219ddf6d119dff272fa2fe16c34990c7d")

        self.assertRaises(ValueError, Radius.parse, packed_message, secret="",
                          radius_lifecycle=namedtuple('RadiusLifecycle', 'packet_id_to_request_authenticator')({
                            0: bytes.fromhex("982a0ba06d3557f0dbc8ba6e823822f1")
                          }))

    def test_radius_access_challenge_parses(self):
        packed_message = bytes.fromhex(
            "0b00005056d9280d3e4fed327eb31cf1823f8c244f1801020016041074d3db089b727d9cc5774599e4a32a295012ecc840b316217c851bd6708afb554b24181219ddf6d119dff272fa2fe16c34990c7d")
        message = Radius.parse(packed_message, secret="SECRET",
                               radius_lifecycle=namedtuple('RadiusLifecycle', 'packet_id_to_request_authenticator')({
                                 0: bytes.fromhex("982a0ba06d3557f0dbc8ba6e823822f1")
                               }))
        self.assertEqual(message.packet_id, 0)
        self.assertEqual(binascii.hexlify(message.authenticator), b"56d9280d3e4fed327eb31cf1823f8c24")
        msg_attr = message.attributes
        self.assertEqual(len(msg_attr.attributes), 3)
        eap_msg = msg_attr.find(EAPMessage.DESCRIPTION).data_type.data()
        self.assertEqual(eap_msg.code, 1)
        self.assertEqual(eap_msg.message_id, 2)
        self.assertEqual(binascii.hexlify(eap_msg.challenge),
                         b"74d3db089b727d9cc5774599e4a32a29")
        self.assertEqual(binascii.hexlify(msg_attr.find(
            MessageAuthenticator.DESCRIPTION).data_type.data()),
                         b"ecc840b316217c851bd6708afb554b24")
        self.assertEqual(binascii.hexlify(msg_attr.find(State.DESCRIPTION).data_type.data()),
                         b"19ddf6d119dff272fa2fe16c34990c7d")

    def test_radius_access_challenge_ttls_parses(self):
        packed_message = bytes.fromhex(
            "0b06042c54dbc73332c00c0347fc4b462d1811a74fff016a03ec15c000000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c6520434fff6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c554fff856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f4ff7302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2501226e219fc875fd78976eb2b9b475b14881812c1591073c33305b4fa8bd26dd27eafd9")
        message = Radius.parse(packed_message, secret="SECRET",
                               radius_lifecycle=namedtuple('RadiusLifecycle', 'packet_id_to_request_authenticator')({
                                 6: bytes.fromhex("0d64ffb8bc76d457d337e5f5692534aa")
                               }))
        self.assertEqual(message.packet_id, 6)
        self.assertEqual(binascii.hexlify(message.authenticator), b"54dbc73332c00c0347fc4b462d1811a7")
        msg_attr = message.attributes
        self.assertEqual(len(msg_attr.attributes), 3)
        eap_msg = msg_attr.find(EAPMessage.DESCRIPTION).data_type.data()
        self.assertEqual(eap_msg.code, 1)
        self.assertEqual(eap_msg.message_id, 106)
        self.assertEqual(eap_msg.flags, 0xc0)
        self.assertEqual(binascii.hexlify(eap_msg.extra_data), b"00000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c652043"
                         b"6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c55"
                         b"856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f"
                         b"302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2")
        self.assertEqual(binascii.hexlify(msg_attr.find(
            MessageAuthenticator.DESCRIPTION).data_type.data()),
                         b"26e219fc875fd78976eb2b9b475b1488")
        self.assertEqual(binascii.hexlify(msg_attr.find(State.DESCRIPTION).data_type.data()),
                         b"c1591073c33305b4fa8bd26dd27eafd9")

    def test_radius_access_challenge_packs(self):
        expected_packed_message = bytes.fromhex("0b06042c"
                                                "54dbc73332c00c0347fc4b462d1811a74fff016a03ec15c000000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c6520434fff6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c554fff856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f4ff7302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2"
                                                "501226e219fc875fd78976eb2b9b475b1488"
                                                "1812c1591073c33305b4fa8bd26dd27eafd9")
        attr_list = list()
        attr_list.append(EAPMessage.create("016a03ec15c000000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c652043"))
        attr_list.append(EAPMessage.create("6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c55"))
        attr_list.append(EAPMessage.create("856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f"))
        attr_list.append(EAPMessage.create("302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2"))
        attr_list.append(MessageAuthenticator.create(
            bytes.fromhex("26e219fc875fd78976eb2b9b475b1488")))
        attr_list.append(State.create(bytes.fromhex("c1591073c33305b4fa8bd26dd27eafd9")))
        attributes = RadiusAttributesList(attr_list)
        access_challenge = RadiusAccessChallenge(6,
                                                 bytes.fromhex("54dbc73332c00c0347fc4b462d1811a7"),
                                                 attributes)
        packed_message = access_challenge.pack()
        self.assertEqual(len(expected_packed_message), len(packed_message))
        self.assertEqual(expected_packed_message, packed_message)

    def test_radius_access_challenge_packs2(self):
        expected_packed_message = bytes.fromhex("0b06042c"
                                                "54dbc73332c00c0347fc4b462d1811a74fff016a03ec15c000000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c6520434fff6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c554fff856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f4ff7302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2"
                                                "501226e219fc875fd78976eb2b9b475b1488"
                                                "1812c1591073c33305b4fa8bd26dd27eafd9")
        attr_list = list()
        attr_list.append(EAPMessage.create(
            "016a03ec15c000000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c652043"
            "6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c55"
            "856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f"
            "302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2"))
        attr_list.append(
            MessageAuthenticator.create(bytes.fromhex("26e219fc875fd78976eb2b9b475b1488")))
        attr_list.append(State.create(bytes.fromhex("c1591073c33305b4fa8bd26dd27eafd9")))
        attributes = RadiusAttributesList(attr_list)
        access_challenge = RadiusAccessChallenge(6,
                                                 bytes.fromhex("54dbc73332c00c0347fc4b462d1811a7"),
                                                 attributes)
        packed_message = access_challenge.pack()
        self.assertEqual(len(expected_packed_message), len(packed_message))
        self.assertEqual(expected_packed_message, packed_message)

    def test_radius_access_request_packs(self):
        expected_packed_message = bytes.fromhex("010e01dc688d6504db3c757243f995d5f0d32e50010b686f737431757365721e1434342d34342d34342d34342d34342d34343a3d06000000130606000000021f1330302d30302d30302d31312d31312d30314d17434f4e4e45435420304d627073203830322e3131622c12433634383030344139433930353537390c06000005784fff02250133150016030101280100012403032c36dbf8ee16b94b28efdb8c5603e07823f9b716557b5ef2624b026daea115760000aac030c02cc028c024c014c00a00a500a300a1009f006b006a0069006800390038003700360088008700860085c032c02ec02ac026c00fc005009d003d00350084c02fc02bc027c023c013c00900a400a200a0009e00670040003f003e0033003200310030009a0099009800970045004400430042c031c02dc029c025c00ec004009c003c002f00960041c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff01000051000b000403000102000a001c001a00170019001c001b0018001a004f3816000e000d000b000c0009000a000d0020001e060106020603050105020503040104020403030103020303020102020203000f0001011812cefe6083cfdb75dd64722c274ec353725012ab67ed568931f12d258f9ffda931159e")

        attr_list = list()
        attr_list.append(UserName.create("host1user"))
        attr_list.append(CalledStationId.create("44-44-44-44-44-44:"))
        attr_list.append(NASPortType.create(0x13))
        attr_list.append(ServiceType.create(0x02))
        attr_list.append(CallingStationId.create("00-00-00-11-11-01"))
        attr_list.append(ConnectInfo.create("CONNECT 0Mbps 802.11b"))
        attr_list.append(AcctSessionId.create("C648004A9C905579"))
        attr_list.append(FramedMTU.create(0x0578))

        attr_list.append(EAPMessage.create(
            "02250133150016030101280100012403032c36dbf8ee16b94b28efdb8c5603e07823f9b716557b5ef2624b026daea115760000aac030c02cc028c024c014c00a00a500a300a1009f006b006a0069006800390038003700360088008700860085c032c02ec02ac026c00fc005009d003d00350084c02fc02bc027c023c013c00900a400a200a0009e00670040003f003e0033003200310030009a0099009800970045004400430042c031c02dc029c025c00ec004009c003c002f00960041c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff01000051000b000403000102000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101"))
        attr_list.append(State.create(bytes.fromhex("cefe6083cfdb75dd64722c274ec35372")))
        attr_list.append(MessageAuthenticator.create(
            bytes.fromhex("00000000000000000000000000000000")))

        attributes = RadiusAttributesList(attr_list)
        access_request = RadiusAccessRequest(14, bytes.fromhex("688d6504db3c757243f995d5f0d32e50"),
                                             attributes)
        packed_message = access_request.build("SECRET")

        self.assertEqual(len(expected_packed_message), len(packed_message))
        self.assertEqual(expected_packed_message, packed_message)

    def test_parse_illegal_radius_datatype_lengths(self):

        self.assertRaises(MessageParseError, Integer.parse, (1500).to_bytes(3, byteorder='big'))
        self.assertRaises(MessageParseError, Integer.parse, bytes.fromhex("01234567890123456789"))

        self.assertRaises(MessageParseError, Enum.parse, bytes.fromhex("000002"))
        self.assertRaises(MessageParseError, Enum.parse, bytes.fromhex("01234567890123456789"))

        self.assertRaises(MessageParseError, Text.parse, "".encode())
        self.assertRaises(MessageParseError, Text.parse,
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName".encode())

        self.assertRaises(MessageParseError, String.parse, "".encode())
        self.assertRaises(MessageParseError, String.parse, "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260Char".encode())

        self.assertRaises(MessageParseError, Vsa.parse, "abcd".encode())
        self.assertRaises(MessageParseError, Vsa.parse,
                          "270CharacterLengthVSAAttribute270CharacterLengthVSAAttribute"
                          "270CharacterLengthVSAAttribute270CharacterLengthVSAAttribute"
                          "270CharacterLengthVSAAttribute270CharacterLengthVSAAttribute"
                          "270CharacterLengthVSAAttribute270CharacterLengthVSAAttribute"
                          "270CharacterLen270CharacterLen".encode())
        # Cannot test Concat datatype, it does not check length

    def test_pack_illegal_radius_datatype_lengths(self):
        self.assertRaises(ValueError, FramedMTU.create, -1)
        self.assertRaises(ValueError, FramedMTU.create, 10000000000)

        self.assertRaises(ValueError, ServiceType.create, -1)
        self.assertRaises(ValueError, ServiceType.create, 10000000000)

        self.assertRaises(ValueError, UserName.create, "")
        self.assertRaises(ValueError, UserName.create,
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName"
                          "260CharacterLengthUserName260CharacterLengthUserName")

        self.assertRaises(ValueError, State.create, "")
        self.assertRaises(ValueError, State.create,
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
        attributes_data = bytes.fromhex("1a3a000001371134904a76cd1ffff59a3e1365e09441c41d83454aedafc1d9099d32ade23714a4d2c0898ff23997c89f59f1149bcb709fb889dc1a3a0000013710349e92efe66d278d977e3fe87faa650b391c43103d3d8e662bb3881807f1b3313ed975d3cfa85d45a6f3b83f6b98364a99135e4f06032a0004501256aef88d10224c30e6b3563acf963758010b686f73743175736572")
        attributes_to_concat = {}
        RadiusAttributesList.extract_attributes(attributes_data, attributes, attributes_to_concat)
        self.assertEqual(len(attributes), 5)
        self.assertEqual(len(attributes_to_concat), 1)
        self.assertEqual(list(attributes_to_concat.values())[0][0][1], 2)
        # check that the concated EAPMessage is marked position 2

        # This list of radius AVP contains multiple EAPMessages.
        attributes = []
        attributes_data = bytes.fromhex("4fff012802bc158000000a76130101ff040530030101ff30360603551d1f042f302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e6f72672f6578616d706c655f63612e63726c300d06092a864886f70d01010b05000382010100139e9c2b1e9bf30c6567759ffb57af9f031a59b6a8adb1702a55de2e51f2286715ef1399ebdc593d38db3ad4794c3e78037d3de5612cba33cefc5b830c3a2118bfc0572d201c07105b7c0ef5bb64225d959afef6a4527a88d1e5fd552fd16775a5c90802d11ad793da157441f7a181f85a2908ebcb87a86960c6d3ae631019bc73f850bc5be494a97084ccaea1cc13c44a4fdf0ef123c067b688e47a4fff4d223c15fd56798051ff4912c721f15c96061ef683b1ade02b5449b06184f59d4218f2287d35cfa0a3a4f65e40c8750d0c70dc00d65a8981e0a2cf6961b1355c10d399ce583a426e211b0feef37da67a57bbbc81d912d5379668cfdc3666bacf5e9d9c7d160303014d0c0001490300174104b275c284c5c067b9c3104305ba6704b4b0e083f0e285d9b205a8d7307e503907478f314679d084a0f1ccbc3ceaa6b6d56c588654d223fd16514bba463c5f8d7006010100bca760ef9aab5f1cf9239bab7d0bbf585e12f9c6440b9dd36affc87ff8f334b0dbea94686edbcff9143bd40a5136b065d5599742665fa27d5ec5e86898b7c8cc2c375d190646c64fc444df7911f41a12a7219f667527cfc4ba99b684fb763a01f4dc361a891906e3ade0c6e787c096f868726a5aafafb76ce71ce896b50015c9db89e9c3d13c90e90b5d82a1327941404298c1e358cbc7bbbf8e4fe2e1ecafbcbddfbe0b1a7d3f0769306f16f3ed4972b14b8af0f51761053754ec73a1a41b294fe0d00a9281e3d9c0175651d2bbaf28df32a25bfbae85983a3935891f0a955b636b3540cde3aba4ec20d62988a81a608b450e87b3eefcb66f50cf3104a4b367122d16030300040e00000050125f3ac1f2c8e65dab1bf90b9604cd65aa1812cefe6083cad675dd64722c274ec35372")
        attributes_to_concat = {}
        RadiusAttributesList.extract_attributes(attributes_data, attributes, attributes_to_concat)
        self.assertEqual(len(attributes), 5)
        self.assertEqual(len(attributes_to_concat), 1)
        # check that the concated EAPMessage is marked position 0
        self.assertEqual(list(attributes_to_concat.values())[0][0][1], 0)

    def test_concat_when_length_multiple_of_max_data_length(self):
        expected_packed = bytes.fromhex("4fff013d03f419c00000144f160303004a020000460303eb4b5ca844e4929c67df4a32d7b0afd05a589cd5bf959dc418b49d91637ace992005c3b271553df564fce2c69100d3fa9db4308cd1a829597b555839afebee02d8003d0016030313f20b0013ee0013eb0008633082085f30820647a00302010202142162b97e20bcdf02f0961f5a34e80ebb682828d9300d06092a864886f70d01010b0500304d310b300906035504061302424d31193017060355040a131051756f5661646973204c696d69746564312330210603550403131a51756f566164697320476c6f62616c2053534c20494341204733301e170d3138313030323233303432375a170d324fff30313030323233313430305a308189310b3009060355040613024e5a3113301106035504080c0a57656c6c696e67746f6e3113301106035504070c0a57656c6c696e67746f6e312a3028060355040a0c21566963746f72696120556e6976657273697479206f662057656c6c696e67746f6e310c300a060355040b0c034954533116301406035504030c0d6973652e7675772e61632e6e7a30820122300d06092a864886f70d01010105000382010f003082010a0282010100ea13ab1ff3d0494bc3aabd994b1aac55877f185bbb11721f39f894f0cebf3fa9a7b4e03d81f6e635b8383146230a4e9e0f81913783edb9a8c47d8adbf5ccb565944fb0d54fffdfc8481b1e43ae4edda80cc3d445b77aa82adc011da13a9f255aa85d8d58bd079f2744d6765b05382acbc51b88bbd54043349b198ba66d82ce50bfa84e75a6d93f9e110099eae544b2aa4fbb22a8d5bffdc578d729ab2550ee73adda13e9eee968dfdf76cd0e70ceaf8977d9a7e575b9b35a83a55b68543d9e1311d02edd3a45b29cd5aa1cb363d4afbcfa4905f06661fb8fe804b99b1ef850ca102054a5ac25bd0069466187a463de736070452e2b75bc3950b420a9bd3fe2dc58e90203010001a38203f8308203f430090603551d1304023000301f0603551d23041830168014b31289b5a94b35bc1500f080e9d87887f1137c76307306082b0601054fff0507010104673065303706082b06010505073002862b687474703a2f2f74727573742e71756f7661646973676c6f62616c2e636f6d2f717673736c67332e637274302a06082b06010505073001861e687474703a2f2f6f6373702e71756f7661646973676c6f62616c2e636f6d3081f20603551d110481ea3081e7820d6973652e7675772e61632e6e7a8219767577766170636f69736570616e312e7675772e61632e6e7a8219767577766170647269736573616e312e7675772e61632e6e7a8219767577766170636f6973656d6f6e312e7675772e61632e6e7a821976757776617064726973656d6f6e312e7675772e61632e6e7a82197675777661")
        big_concat_bytes = bytes.fromhex("013d03f419c00000144f160303004a020000460303eb4b5ca844e4929c67df4a32d7b0afd05a589cd5bf959dc418b49d91637ace992005c3b271553df564fce2c69100d3fa9db4308cd1a829597b555839afebee02d8003d0016030313f20b0013ee0013eb0008633082085f30820647a00302010202142162b97e20bcdf02f0961f5a34e80ebb682828d9300d06092a864886f70d01010b0500304d310b300906035504061302424d31193017060355040a131051756f5661646973204c696d69746564312330210603550403131a51756f566164697320476c6f62616c2053534c20494341204733301e170d3138313030323233303432375a170d3230313030323233313430305a308189310b3009060355040613024e5a3113301106035504080c0a57656c6c696e67746f6e3113301106035504070c0a57656c6c696e67746f6e312a3028060355040a0c21566963746f72696120556e6976657273697479206f662057656c6c696e67746f6e310c300a060355040b0c034954533116301406035504030c0d6973652e7675772e61632e6e7a30820122300d06092a864886f70d01010105000382010f003082010a0282010100ea13ab1ff3d0494bc3aabd994b1aac55877f185bbb11721f39f894f0cebf3fa9a7b4e03d81f6e635b8383146230a4e9e0f81913783edb9a8c47d8adbf5ccb565944fb0d5dfc8481b1e43ae4edda80cc3d445b77aa82adc011da13a9f255aa85d8d58bd079f2744d6765b05382acbc51b88bbd54043349b198ba66d82ce50bfa84e75a6d93f9e110099eae544b2aa4fbb22a8d5bffdc578d729ab2550ee73adda13e9eee968dfdf76cd0e70ceaf8977d9a7e575b9b35a83a55b68543d9e1311d02edd3a45b29cd5aa1cb363d4afbcfa4905f06661fb8fe804b99b1ef850ca102054a5ac25bd0069466187a463de736070452e2b75bc3950b420a9bd3fe2dc58e90203010001a38203f8308203f430090603551d1304023000301f0603551d23041830168014b31289b5a94b35bc1500f080e9d87887f1137c76307306082b0601050507010104673065303706082b06010505073002862b687474703a2f2f74727573742e71756f7661646973676c6f62616c2e636f6d2f717673736c67332e637274302a06082b06010505073001861e687474703a2f2f6f6373702e71756f7661646973676c6f62616c2e636f6d3081f20603551d110481ea3081e7820d6973652e7675772e61632e6e7a8219767577766170636f69736570616e312e7675772e61632e6e7a8219767577766170647269736573616e312e7675772e61632e6e7a8219767577766170636f6973656d6f6e312e7675772e61632e6e7a821976757776617064726973656d6f6e312e7675772e61632e6e7a82197675777661")
        concat = Concat(bytes_data=big_concat_bytes)
        packed = concat.pack(EAPMessage.TYPE)
        self.assertEqual(expected_packed, packed)
