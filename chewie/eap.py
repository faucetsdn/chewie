import struct

class EapIdentity(object):
    def __init__(self, identity):
        self.identity = identity

    @classmethod
    def parse(cls, packed_message):
        return cls(packed_message)

    def __repr__(self):
        return "%s(identity=%s)" % \
            (self.__class__.__name__, self.identity)

class EapMd5Challenge(object):
    def __init__(self, value, extra_data):
        self.value = value
        self.extra_data = extra_data

    @classmethod
    def parse(cls, packed_message):
        value_length, = struct.unpack("!B", packed_message[:1])
        value = packed_message[1:1+value_length]
        extra_data = packed_message[1+value_length:]
        return cls(value, extra_data)

    def __repr__(self):
        return "%s(value=%s, extra_data=%s)" % \
            (self.__class__.__name__, self.value, self.extra_data)

EAP_HEADER_LENGTH = 1 + 1 + 2 + 1

class Eap:
    def __init__(self, code, packet_id, length, packet_type, data):
        self.code = code
        self.packet_id = packet_id
        self.length = length
        self.packet_type = packet_type
        self.data = data

    @classmethod
    def parse(cls, packed_message):
        code, packet_id, length, packet_type = struct.unpack("!BBHB", packed_message[:EAP_HEADER_LENGTH])
        data = packed_message[EAP_HEADER_LENGTH:EAP_HEADER_LENGTH+length]
        return cls(code, packet_id, length, packet_type, data)