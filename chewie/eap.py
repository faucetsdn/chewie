import struct

class EapIdentity(object):
    PACKET_TYPE = 1

    def __init__(self, eap_header, identity):
        self.code = eap_header.code
        self.packet_id = eap_header.packet_id
        self.identity = identity.decode()

    @classmethod
    def parse(cls, eap_header, packed_message):
        return cls(eap_header, packed_message)

    def __repr__(self):
        return "%s(identity=%s)" % \
            (self.__class__.__name__, self.identity)

class EapMd5Challenge(object):
    PACKET_TYPE = 4

    def __init__(self, eap_header, challenge, extra_data):
        self.code = eap_header.code
        self.packet_id = eap_header.packet_id
        self.challenge = challenge
        self.extra_data = extra_data

    @classmethod
    def parse(cls, eap_header, packed_message):
        value_length, = struct.unpack("!B", packed_message[:1])
        challenge = packed_message[1:1+value_length]
        extra_data = packed_message[1+value_length:]
        return cls(eap_header, challenge, extra_data)

    def __repr__(self):
        return "%s(challenge=%s, extra_data=%s)" % \
            (self.__class__.__name__, self.challenge, self.extra_data)

EAP_HEADER_LENGTH = 1 + 1 + 2 + 1

PARSERS = {
    1: EapIdentity,
    4: EapMd5Challenge,
}

class Eap:
    REQUEST = 1
    RESPONSE = 2
    IDENTITY = 1
    MD5_CHALLENGE = 4
    def __init__(self, code, packet_id, length, packet_type):
        self.code = code
        self.packet_id = packet_id
        self.length = length
        self.packet_type = packet_type

    @classmethod
    def parse(cls, packed_message):
        code, packet_id, length, packet_type = struct.unpack("!BBHB", packed_message[:EAP_HEADER_LENGTH])
        data = packed_message[EAP_HEADER_LENGTH:EAP_HEADER_LENGTH+length]
        eap_header = cls(code, packet_id, length, packet_type)
        return PARSERS[packet_type].parse(eap_header, data)
