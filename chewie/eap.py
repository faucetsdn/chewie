import struct

EAP_HEADER_LENGTH = 1 + 1 + 2 + 1

PARSERS = {}

class Eap(object):
    REQUEST = 1
    RESPONSE = 2
    IDENTITY = 1
    MD5_CHALLENGE = 4

    @staticmethod
    def parse(packed_message):
        code, packet_id, length, packet_type = struct.unpack("!BBHB", packed_message[:EAP_HEADER_LENGTH])
        data = packed_message[EAP_HEADER_LENGTH:length]
        return PARSERS[packet_type](code, packet_id, data)

    def pack(self, packed_body):
        header = struct.pack("!BBHB", self.code, self.packet_id, EAP_HEADER_LENGTH + len(packed_body), self.PACKET_TYPE)
        return header + packed_body

def register_parser(cls):
    PARSERS[cls.PACKET_TYPE] = cls.parse
    return cls

@register_parser
class EapIdentity(Eap):
    PACKET_TYPE = 1

    def __init__(self, code, packet_id, identity):
        self.code = code
        self.packet_id = packet_id
        self.identity = identity

    @classmethod
    def parse(cls, code, packet_id, packed_message):
        return cls(code, packet_id, packed_message.decode())

    def pack(self):
        packed_identity = self.identity.encode()
        return super(EapIdentity, self).pack(packed_identity)

    def __repr__(self):
        return "%s(identity=%s)" % \
            (self.__class__.__name__, self.identity)

@register_parser
class EapMd5Challenge(Eap):
    PACKET_TYPE = 4

    def __init__(self, code, packet_id, challenge, extra_data):
        self.code = code
        self.packet_id = packet_id
        self.challenge = challenge
        self.extra_data = extra_data

    @classmethod
    def parse(cls, code, packet_id, packed_message):
        value_length, = struct.unpack("!B", packed_message[:1])
        challenge = packed_message[1:1+value_length]
        extra_data = packed_message[1+value_length:]
        return cls(code, packet_id, challenge, extra_data)

    def pack(self):
        value_length = struct.pack("!B", len(self.challenge))
        packed_md5_challenge = value_length + self.challenge + self.extra_data
        return super(EapMd5Challenge, self).pack(packed_md5_challenge)

    def __repr__(self):
        return "%s(challenge=%s, extra_data=%s)" % \
            (self.__class__.__name__, self.challenge, self.extra_data)
