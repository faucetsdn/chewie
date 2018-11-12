"""Module for parsing & packing EAP"""

import struct

EAP_HEADER_LENGTH = 1 + 1 + 2
EAP_TYPE_LENGTH = 1

PARSERS = {}
PARSERS_TYPES = {}


class Eap:
    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4

    IDENTITY = 1
    LEGACY_NAK = 3
    MD5_CHALLENGE = 4
    TLS = 13
    TTLS = 21

    code = None
    packet_id = None
    PACKET_TYPE = None

    @staticmethod
    def parse(packed_message):
        code, packet_id, length = struct.unpack("!BBH", packed_message[:EAP_HEADER_LENGTH])
        if code in (Eap.REQUEST, Eap.RESPONSE):
            packet_type, = struct.unpack("!B",
                                         packed_message[EAP_HEADER_LENGTH :
                                                        EAP_HEADER_LENGTH + EAP_TYPE_LENGTH])
            data = packed_message[EAP_HEADER_LENGTH+EAP_TYPE_LENGTH:length]
            return PARSERS[packet_type](code, packet_id, packet_type, data)
        elif code == Eap.SUCCESS:
            return EapSuccess(packet_id)
        elif code == Eap.FAILURE:
            return EapFailure(packet_id)
        raise ValueError("Got Eap packet with bad code: %s" % packed_message)

    def pack(self, packed_body):
        header = struct.pack("!BBHB", self.code, self.packet_id,
                             EAP_HEADER_LENGTH + EAP_TYPE_LENGTH + len(packed_body),
                             self.PACKET_TYPE)
        return header + packed_body



def register_parser(packet_types=None):
    def wrapped(cls):
        if not packet_types:
            PARSERS[cls.PACKET_TYPE] = cls.parse
        else:
            for packet_type in packet_types:
                PARSERS[packet_type] = cls.parse
        return cls
    return wrapped


@register_parser()
class EapIdentity(Eap):
    PACKET_TYPE = 1

    def __init__(self, code, packet_id, identity):
        self.code = code
        self.packet_id = packet_id
        self.identity = identity

    @classmethod
    def parse(cls, code, packet_id, packet_type, packed_message):
        return cls(code, packet_id, packed_message.decode())

    def pack(self):
        packed_identity = self.identity.encode()
        return super(EapIdentity, self).pack(packed_identity)

    def __repr__(self):
        return "%s(identity=%s)" % \
            (self.__class__.__name__, self.identity)


class EapSuccess(Eap):
    def __init__(self, packet_id):
        self.packet_id = packet_id

    @classmethod
    def parse(cls, packet_id):
        return cls(packet_id)

    def pack(self):
        return struct.pack("!BBH", Eap.SUCCESS, self.packet_id, EAP_HEADER_LENGTH)

    def __repr__(self):
        return "%s(packet_id=%s)" % \
            (self.__class__.__name__, self.packet_id)


class EapFailure(Eap):
    def __init__(self, packet_id):
        self.packet_id = packet_id

    @classmethod
    def parse(cls, packet_id):
        return cls(packet_id)

    def pack(self):
        return struct.pack("!BBH", Eap.FAILURE, self.packet_id, EAP_HEADER_LENGTH)

    def __repr__(self):
        return "%s(packet_id=%s)" % \
            (self.__class__.__name__, self.packet_id)

@register_parser(packet_types=[Eap.LEGACY_NAK, Eap.MD5_CHALLENGE, Eap.TTLS])
class EapGeneric(Eap):
    """Handles the EAP method e.g. TLS, TTLS, MD5, ..."""
    PACKET_TYPE = -1


    def __init__(self, code, packet_id, packet_type, extra_data):
        self.code = code
        self.packet_id = packet_id
        self.PACKET_TYPE = packet_type
        self.extra_data = extra_data

    @classmethod
    def parse(cls, code, packet_id, packet_type, packed_msg):
        value_len = len(packed_msg)
        fmt_str = "!"
        if value_len > 0:
            fmt_str += "%ds" % (value_len)
        unpacked = struct.unpack(fmt_str, packed_msg)
        extra_data = b""
        if value_len > 0:
            extra_data = unpacked[0]

        return cls(code, packet_id, packet_type, extra_data)

    def pack(self):
        if self.extra_data:
            print('extra_data', self.extra_data)
            packed = struct.pack("!%ds" % len(self.extra_data), self.extra_data)
        else:
            packed = b''
        return super().pack(packed)

    def __repr__(self):
        return "%s(packet_id=%s, extra_data=%s)" % \
            (self.__class__.__name__, self.packet_id, self.extra_data)
