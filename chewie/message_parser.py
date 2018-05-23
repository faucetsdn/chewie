from .ethernet_packet import EthernetPacket
from .auth_8021x import Auth8021x
from .eap import Eap, EapIdentity, EapMd5Challenge, EapSuccess, EapFailure
from .mac_address import MacAddress

class SuccessMessage(object):
    def __init__(self, src_mac, message_id):
        self.src_mac = src_mac
        self.message_id = message_id

    @classmethod
    def build(cls, src_mac, eap):
        return cls(src_mac, eap.packet_id)

class FailureMessage(object):
    def __init__(self, src_mac, message_id):
        self.src_mac = src_mac
        self.message_id = message_id

    @classmethod
    def build(cls, src_mac, eap):
        return cls(src_mac, eap.packet_id)

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

class EapolStartMessage(object):
    def __init__(self, src_mac):
        self.src_mac = src_mac

    @classmethod
    def build(cls, src_mac):
        return cls(src_mac)

class EapolLogoffMessage(object):
    def __init__(self, src_mac):
        self.src_mac = src_mac

    @classmethod
    def build(cls, src_mac):
        return cls(src_mac)

EAP_MESSAGES = {
    Eap.IDENTITY: IdentityMessage,
    Eap.MD5_CHALLENGE: Md5ChallengeMessage,
}

AUTH_8021X_MESSAGES = {
    0: "eap",
    1: "eapol start",
}

class MessageParser:
    @staticmethod
    def parse(packed_message):
        ethernet_packet = EthernetPacket.parse(packed_message)
        if ethernet_packet.ethertype != 0x888e:
            raise ValueError("Ethernet packet with bad ethertype received: %s" % ethernet_packet)
        auth_8021x = Auth8021x.parse(ethernet_packet.data)
        if auth_8021x.packet_type == 0:
            eap = Eap.parse(auth_8021x.data)
            if isinstance(eap, EapIdentity) or isinstance(eap, EapMd5Challenge):
                return EAP_MESSAGES[eap.PACKET_TYPE].build(ethernet_packet.src_mac, eap)
            elif isinstance(eap, EapSuccess):
                return SuccessMessage.build(ethernet_packet.src_mac, eap)
            elif isinstance(eap, EapFailure):
                return FailureMessage.build(ethernet_packet.src_mac, eap)
            else:
                raise ValueError("Got bad Eap packet: %s" % eap)
        elif auth_8021x.packet_type == 1:
            return EapolStartMessage.build(ethernet_packet.src_mac)
        elif auth_8021x.packet_type == 2:
            return EapolLogoffMessage.build(ethernet_packet.src_mac)
        raise ValueError("802.1x has bad type, expected 0: %s" % auth_8021x)

class MessagePacker:
    @staticmethod
    def pack(message):
        if isinstance(message, IdentityMessage):
            eap = EapIdentity(message.code, message.message_id, message.identity)
            auth_8021x = Auth8021x(version=1, packet_type=0, data=eap.pack())
        elif isinstance(message, Md5ChallengeMessage):
            eap = EapMd5Challenge(message.code, message.message_id, message.challenge, message.extra_data)
            auth_8021x = Auth8021x(version=1, packet_type=0, data=eap.pack())
        elif isinstance(message, SuccessMessage):
            eap = EapSuccess(message.message_id)
            auth_8021x = Auth8021x(version=1, packet_type=0, data=eap.pack())
        elif isinstance(message, FailureMessage):
            eap = EapFailure(message.message_id)
            auth_8021x = Auth8021x(version=1, packet_type=0, data=eap.pack())
        elif isinstance(message, EapolStartMessage):
            auth_8021x = Auth8021x(version=1, packet_type=1, data=b"")
        elif isinstance(message, EapolLogoffMessage):
            auth_8021x = Auth8021x(version=1, packet_type=2, data=b"")
        else:
            raise ValueError("Cannot pack message: %s" % message)
        ethernet_packet = EthernetPacket(dst_mac=MacAddress.from_string("01:80:c2:00:00:03"), src_mac=message.src_mac, ethertype=0x888e, data=auth_8021x.pack())
        return ethernet_packet.pack()

