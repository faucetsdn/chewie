import unittest
from netils import build_byte_string
from chewie.radius import *
from chewie.radius_attributes import UserName, ServiceType, FramedMTU, CalledStationId, AcctSessionId, NASPortType, \
    ConnectInfo, EAPMessage, MessageAuthenticator, State, VendorSpecific, CallingStationId
from chewie.radius_datatypes import Vsa, String, Enum, Text, Integer


class RadiusTestCase(unittest.TestCase):
    def test_radius_access_request_parses(self):
        packed_message = build_byte_string("010000a3982a0ba06d3557f0dbc8ba6e823822f1010b686f737431757365721e1434342d34342d34342d34342d34342d34343a3d06000000130606000000021f1330302d30302d30302d31312d31312d30314d17434f4e4e45435420304d627073203830322e3131622c12433634383030344139433930353537390c06000005784f100201000e01686f73743175736572501273f82750f6f261a95a7cc7d318b9f573")
        message = Radius.parse(packed_message, secret="SECRET")
        self.assertEqual(message.packet_id, 0)
        self.assertEqual(message.authenticator, "982a0ba06d3557f0dbc8ba6e823822f1")
        msg_attr = message.attributes
        self.assertEqual(len(msg_attr.attributes), 10)
        self.assertEqual(msg_attr.find(UserName.DESCRIPTION).data_type.data(), 'host1user')
        self.assertEqual(msg_attr.find(CalledStationId.DESCRIPTION).data_type.data(), "44-44-44-44-44-44:")
        self.assertEqual(msg_attr.find(NASPortType.DESCRIPTION).data_type.data(), 19)
        self.assertEqual(msg_attr.find(ServiceType.DESCRIPTION).data_type.data(), 2)
        self.assertEqual(msg_attr.find(ConnectInfo.DESCRIPTION).data_type.data(), "CONNECT 0Mbps 802.11b")
        self.assertEqual(msg_attr.find(AcctSessionId.DESCRIPTION).data_type.data(), "C648004A9C905579")
        self.assertEqual(msg_attr.find(FramedMTU.DESCRIPTION).data_type.data(), 1400)
        self.assertEqual(msg_attr.find(EAPMessage.DESCRIPTION).data_type.data().hex(), "0201000e01686f73743175736572")
        self.assertEqual(msg_attr.find(MessageAuthenticator.DESCRIPTION).data_type.data().hex(), "73f82750f6f261a95a7cc7d318b9f573")

    def test_radius_access_accept_parses(self):
        packed_message = build_byte_string("0201004602970aff2ef0700780f70848e90d24101a0f00003039010973747564656e744f06030200045012d7ec84e8864dd6cd00916c1d5a3cf41b010b686f73743175736572")
        message = Radius.parse(packed_message, secret="SECRET", request_authenticator=bytes.fromhex("a0b4ace0b367114b1a16d76e2bfed5d8"))
        self.assertEqual(message.packet_id, 1)
        self.assertEqual(message.authenticator, "02970aff2ef0700780f70848e90d2410")
        msg_attr = message.attributes
        self.assertEqual(len(msg_attr.attributes), 4)
        self.assertEqual(msg_attr.find(EAPMessage.DESCRIPTION).data_type.data().hex(), "03020004")
        self.assertEqual(msg_attr.find(MessageAuthenticator.DESCRIPTION).data_type.data().hex(), "d7ec84e8864dd6cd00916c1d5a3cf41b")
        self.assertEqual(msg_attr.find(UserName.DESCRIPTION).data_type.data(), 'host1user')

    def test_radius_access_accept_packs(self):
        expected_packed_message = build_byte_string("02010046"
                                                    "02970aff2ef0700780f70848e90d2410"
                                                    "1a0f00003039010973747564656e74"
                                                    "4f0603020004"
                                                    "5012d7ec84e8864dd6cd00916c1d5a3cf41b"
                                                    "010b686f73743175736572")
        attr_list = list()
        attr_list.append(VendorSpecific.create(bytes.fromhex("00003039010973747564656e74")))
        attr_list.append(EAPMessage.create("03020004"))
        attr_list.append(MessageAuthenticator.create(bytes.fromhex("d7ec84e8864dd6cd00916c1d5a3cf41b")))
        attr_list.append(UserName.create("host1user"))
        attributes = RadiusAttributesList(attr_list)
        access_accept = RadiusAccessAccept(1, bytes.fromhex("02970aff2ef0700780f70848e90d2410"), attributes)
        packed_message = access_accept.pack()
        self.assertEqual(len(expected_packed_message), len(packed_message))
        self.assertEqual(expected_packed_message, packed_message)

    def test_invalid_message_authenticator(self):
        packed_message = build_byte_string(
            "0b00005056d9280d3e4fed327eb31cf1823f8c244f1801020016041074d3db089b727d9cc5774599e4a32a29501266666666666666666666666666666666181219ddf6d119dff272fa2fe16c34990c7d")

        self.assertRaises(InvalidMessageAuthenticatorError, Radius.parse, packed_message, secret="SECRET", request_authenticator=bytes.fromhex("982a0ba06d3557f0dbc8ba6e823822f1"))

    def test_secret_none_fails(self):
        packed_message = build_byte_string(
            "0b00005056d9280d3e4fed327eb31cf1823f8c244f1801020016041074d3db089b727d9cc5774599e4a32a295012ecc840b316217c851bd6708afb554b24181219ddf6d119dff272fa2fe16c34990c7d")

        self.assertRaises(ValueError, Radius.parse, packed_message, secret="", request_authenticator=bytes.fromhex("982a0ba06d3557f0dbc8ba6e823822f1"))


    def test_radius_access_challenge_parses(self):
        packed_message = build_byte_string(
            "0b00005056d9280d3e4fed327eb31cf1823f8c244f1801020016041074d3db089b727d9cc5774599e4a32a295012ecc840b316217c851bd6708afb554b24181219ddf6d119dff272fa2fe16c34990c7d")
        message = Radius.parse(packed_message, secret="SECRET", request_authenticator=bytes.fromhex("982a0ba06d3557f0dbc8ba6e823822f1"))
        self.assertEqual(message.packet_id, 0)
        self.assertEqual(message.authenticator, "56d9280d3e4fed327eb31cf1823f8c24")
        msg_attr = message.attributes
        self.assertEqual(len(msg_attr.attributes), 3)
        self.assertEqual(msg_attr.find(EAPMessage.DESCRIPTION).data_type.data().hex(), "01020016041074d3db089b727d9cc5774599e4a32a29")
        self.assertEqual(msg_attr.find(MessageAuthenticator.DESCRIPTION).data_type.data().hex(), "ecc840b316217c851bd6708afb554b24")
        self.assertEqual(msg_attr.find(State.DESCRIPTION).data_type.data().hex(), "19ddf6d119dff272fa2fe16c34990c7d")

    def test_radius_access_challenge_ttls_parses(self):
        packed_message = build_byte_string(
            "0b06042c54dbc73332c00c0347fc4b462d1811a74fff016a03ec15c000000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c6520434fff6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c554fff856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f4ff7302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2501226e219fc875fd78976eb2b9b475b14881812c1591073c33305b4fa8bd26dd27eafd9")
        message = Radius.parse(packed_message, secret="SECRET", request_authenticator=bytes.fromhex("0d64ffb8bc76d457d337e5f5692534aa"))
        self.assertEqual(message.packet_id, 6)
        self.assertEqual(message.authenticator, "54dbc73332c00c0347fc4b462d1811a7")
        msg_attr = message.attributes
        self.assertEqual(len(msg_attr.attributes), 3)
        self.assertEqual(msg_attr.find(EAPMessage.DESCRIPTION).data_type.data().hex(), "016a03ec15c000000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c652043"
                         "6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c55"
                         "856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f"
                         "302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2")
        self.assertEqual(msg_attr.find(MessageAuthenticator.DESCRIPTION).data_type.data().hex(), "26e219fc875fd78976eb2b9b475b1488")
        self.assertEqual(msg_attr.find(State.DESCRIPTION).data_type.data().hex(), "c1591073c33305b4fa8bd26dd27eafd9")

    def test_radius_access_challenge_packs(self):
        expected_packed_message = build_byte_string("0b06042c"
                                                    "54dbc73332c00c0347fc4b462d1811a74fff016a03ec15c000000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c6520434fff6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c554fff856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f4ff7302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2"
                                                    "501226e219fc875fd78976eb2b9b475b1488"
                                                    "1812c1591073c33305b4fa8bd26dd27eafd9")
        attr_list = list()
        attr_list.append(EAPMessage.create("016a03ec15c000000a76160303003e0200003a0303114aa9dae3f9d452ca12535b03aee03cd4dabe3ca7639929dd3b645d1f86ad6500c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c652043"))
        attr_list.append(EAPMessage.create("6572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c55"))
        attr_list.append(EAPMessage.create("856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f"))
        attr_list.append(EAPMessage.create("302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b2"))
        attr_list.append(MessageAuthenticator.create(bytes.fromhex("26e219fc875fd78976eb2b9b475b1488")))
        attr_list.append(State.create(bytes.fromhex("c1591073c33305b4fa8bd26dd27eafd9")))
        attributes = RadiusAttributesList(attr_list)
        access_challenge = RadiusAccessChallenge(6, bytes.fromhex("54dbc73332c00c0347fc4b462d1811a7"), attributes)
        packed_message = access_challenge.pack()
        self.assertEqual(len(expected_packed_message), len(packed_message))
        self.assertEqual(expected_packed_message, packed_message)

    def test_radius_access_challenge_packs2(self):
        expected_packed_message = build_byte_string("0b06042c"
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
        access_challenge = RadiusAccessChallenge(6, bytes.fromhex("54dbc73332c00c0347fc4b462d1811a7"),
                                                 attributes)
        packed_message = access_challenge.pack()
        self.assertEqual(len(expected_packed_message), len(packed_message))
        self.assertEqual(expected_packed_message, packed_message)

    def test_radius_access_request_packs(self):
        expected_packed_message = build_byte_string("010e01dc688d6504db3c757243f995d5f0d32e50010b686f737431757365721e1434342d34342d34342d34342d34342d34343a3d06000000130606000000021f1330302d30302d30302d31312d31312d30314d17434f4e4e45435420304d627073203830322e3131622c12433634383030344139433930353537390c06000005784fff02250133150016030101280100012403032c36dbf8ee16b94b28efdb8c5603e07823f9b716557b5ef2624b026daea115760000aac030c02cc028c024c014c00a00a500a300a1009f006b006a0069006800390038003700360088008700860085c032c02ec02ac026c00fc005009d003d00350084c02fc02bc027c023c013c00900a400a200a0009e00670040003f003e0033003200310030009a0099009800970045004400430042c031c02dc029c025c00ec004009c003c002f00960041c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff01000051000b000403000102000a001c001a00170019001c001b0018001a004f3816000e000d000b000c0009000a000d0020001e060106020603050105020503040104020403030103020303020102020203000f0001011812cefe6083cfdb75dd64722c274ec353725012ab67ed568931f12d258f9ffda931159e")

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
        attr_list.append(MessageAuthenticator.create(bytes.fromhex("00000000000000000000000000000000")))

        attributes = RadiusAttributesList(attr_list)
        access_request = RadiusAccessRequest(14, bytes.fromhex("688d6504db3c757243f995d5f0d32e50"), attributes)
        packed_message = access_request.build("SECRET")

        self.assertEqual(len(expected_packed_message), len(packed_message))
        self.assertEqual(expected_packed_message, packed_message)

    def test_parse_illegal_radius_datatype_lengths(self):

        self.assertRaises(ValueError, Integer.parse, (1500).to_bytes(3, byteorder='big'))
        self.assertRaises(ValueError, Integer.parse, bytes.fromhex("01234567890123456789"))

        self.assertRaises(ValueError, Enum.parse, bytes.fromhex("000002"))
        self.assertRaises(ValueError, Enum.parse, bytes.fromhex("01234567890123456789"))

        self.assertRaises(ValueError, Text.parse, "".encode())
        self.assertRaises(ValueError, Text.parse, "260CharacterLengthUserName260CharacterLengthUserName"
                                                  "260CharacterLengthUserName260CharacterLengthUserName"
                                                  "260CharacterLengthUserName260CharacterLengthUserName"
                                                  "260CharacterLengthUserName260CharacterLengthUserName"
                                                  "260CharacterLengthUserName260CharacterLengthUserName".encode())

        self.assertRaises(ValueError, String.parse, "".encode())
        self.assertRaises(ValueError, String.parse, "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260Char".encode())

        self.assertRaises(ValueError, Vsa.parse, "abcd".encode())
        self.assertRaises(ValueError, Vsa.parse, "270CharacterLengthVSAAttribute270CharacterLengthVSAAttribute"
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
        self.assertRaises(ValueError, UserName.create, "260CharacterLengthUserName260CharacterLengthUserName"
                                                       "260CharacterLengthUserName260CharacterLengthUserName"
                                                       "260CharacterLengthUserName260CharacterLengthUserName"
                                                       "260CharacterLengthUserName260CharacterLengthUserName"
                                                       "260CharacterLengthUserName260CharacterLengthUserName")

        self.assertRaises(ValueError, State.create, "")
        self.assertRaises(ValueError, State.create, "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260CharacterLengthState"
                                                    "260CharacterLengthState260Char")

        # Cannot test Concat datatype, it does not check length
        # Cannot test VSA datatype, Nothing is using it at the moment.
