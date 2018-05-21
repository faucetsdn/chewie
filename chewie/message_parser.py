from .ethernet_packet import EthernetPacket
from .auth_8021x import Auth8021x
from .eap import Eap, EapIdentity, EapMd5Challenge
from .mac_address import MacAddress

class IdentityMessage(object):
    def __init__(self, src_mac, message_id, code, identity):
        self.src_mac = src_mac
        self.message_id = message_id
        self.code = code
        self.identity = identity

    @classmethod
    def build(cls, src_mac, eap):
        return cls(src_mac, eap.packet_id, eap.code, eap.identity)

class Md5ChallengeMessage(object):
    def __init__(self, src_mac, message_id, code, challenge, extra_data):
        self.src_mac = src_mac
        self.message_id = message_id
        self.code = code
        self.challenge = challenge
        self.extra_data = extra_data

    @classmethod
    def build(cls, src_mac, eap):
        return cls(src_mac, eap.packet_id, eap.code, eap.challenge, eap.extra_data)

MESSAGES = {
    Eap.IDENTITY: IdentityMessage,
    Eap.MD5_CHALLENGE: Md5ChallengeMessage,
}

class MessageParser:
    @staticmethod
    def parse(packed_message):
        ethernet_packet = EthernetPacket.parse(packed_message)
        if ethernet_packet.ethertype != 0x888e:
            raise ValueError("Ethernet packet with bad ethertype received: %s" % ethernet_packet)
        auth_8021x = Auth8021x.parse(ethernet_packet.data)
        if auth_8021x.packet_type != 0:
            raise ValueError("802.1x has bad type, expected 0: %s" % auth_8021x)
        eap = Eap.parse(auth_8021x.data)
        return MESSAGES[eap.PACKET_TYPE].build(ethernet_packet.src_mac, eap)

class MessagePacker:
    @staticmethod
    def pack(message):
        if isinstance(message, IdentityMessage):
            eap = EapIdentity(message.code, message.message_id, message.identity)
            auth_8021x = Auth8021x(version=1, packet_type=0, data=eap.pack())
        elif isinstance(message, Md5ChallengeMessage):
            eap = EapMd5Challenge(message.code, message.message_id, message.challenge, message.extra_data)
            auth_8021x = Auth8021x(version=1, packet_type=0, data=eap.pack())
        ethernet_packet = EthernetPacket(dst_mac=MacAddress.from_string("01:80:c2:00:00:03"), src_mac=message.src_mac, ethertype=0x888e, data=auth_8021x.pack())
        return ethernet_packet.pack()

