from .ethernet_packet import EthernetPacket
from .auth_8021x import Auth8021x
from .eap import Eap

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
