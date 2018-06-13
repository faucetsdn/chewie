import hmac
import struct

from chewie.radius_attributes import ATTRIBUTE_TYPES, Attribute, MessageAuthenticator
from chewie.radius_datatypes import Concat


RADIUS_HEADER_LENGTH = 1 + 1 + 2 + 16

PACKET_TYPE_PARSERS = {}


class Radius(object):
    ACCESS_REQUEST = 1
    ACCESS_ACCEPT = 2
    ACCESS_REJECT = 3
    ACCOUNTING_REQUEST = 4
    ACCOUNTING_RESPONSE = 5
    ACCESS_CHALLENGE = 11
    STATUS_SERVER = 12
    STATUS_CLIENT = 13

    @staticmethod
    def parse(packed_message):
        code, packet_id, length, authenticator = struct.unpack("!BBH16s", packed_message[:RADIUS_HEADER_LENGTH])
        authenticator = authenticator.hex()
        if code in PACKET_TYPE_PARSERS.keys():
            return PACKET_TYPE_PARSERS[code](packet_id, authenticator,
                                             RadiusAttributesList.parse(packed_message[RADIUS_HEADER_LENGTH:]))

    def pack(self, packed_body):
        pass


def register_packet_type_parser(cls):
    PACKET_TYPE_PARSERS[cls.CODE] = cls.parse
    return cls


class RadiusPacket(Radius):
    CODE = None
    packed = None

    def __init__(self, packet_id, authenticator, attributes):
        self.packet_id = packet_id
        self.authenticator = authenticator
        self.attributes = attributes

    @classmethod
    def parse(cls, packet_id, request_authenticator, attributes):
        return cls(packet_id, request_authenticator, attributes)

    def pack(self):
        header = struct.pack("!BBH16s", self.CODE, self.packet_id,
                             RADIUS_HEADER_LENGTH + self.attributes.__len__(),
                             bytes.fromhex(self.authenticator))
        packed_attributes = self.attributes.pack()
        self.packed = bytearray(header + packed_attributes)
        return self.packed

    def build(self, secret=None):
        """Only call this once, or else the MessageAuthenticator will not be zeros, resulting in the wrong hash"""
        if not self.packed:
            self.packed = self.pack()
        if secret and self.attributes.find(MessageAuthenticator.DESCRIPTION):
            message_authenticator = bytearray(hmac.new(secret.encode(), self.packed, 'md5').digest())
            position = self.attributes.index(MessageAuthenticator.DESCRIPTION)

            for i in range(16):
                self.packed[i+position] = message_authenticator[i]
        return self.packed


@register_packet_type_parser
class RadiusAccessRequest(RadiusPacket):
    CODE = Radius.ACCESS_REQUEST


@register_packet_type_parser
class RadiusAccessAccept(RadiusPacket):
    CODE = Radius.ACCESS_ACCEPT


@register_packet_type_parser
class RadiusAccessReject(RadiusPacket):
    CODE = Radius.ACCESS_REJECT


@register_packet_type_parser
class RadiusAccessChallenge(RadiusPacket):
    CODE = Radius.ACCESS_CHALLENGE


class RadiusAttributesList(object):

    def __init__(self, attributes):
        self.attributes = attributes

    @classmethod
    def parse(cls, attributes_data):
        total_length = len(attributes_data)
        i = 0
        attributes = []
        attributes_to_concat = {}
        while i < total_length:
            type_, attr_length = struct.unpack("!BB", attributes_data[i:i + Attribute.HEADER_SIZE])
            data = attributes_data[i + Attribute.HEADER_SIZE: i + attr_length]
            length = attr_length - Attribute.HEADER_SIZE
            packed_value = data[:attr_length - Attribute.HEADER_SIZE]

            attribute = ATTRIBUTE_TYPES[type_].parse(length, packed_value)

            if attribute.DATA_TYPE.DATA_TYPE_VALUE == Concat.DATA_TYPE_VALUE:
                if attribute.TYPE not in attributes_to_concat:
                    attributes_to_concat[attribute.TYPE] = []
                attributes_to_concat[attribute.TYPE].append(attribute)

            attributes.append(attribute)

            i = i + attr_length

        # Join Attributes that's datatype is Concat into one attribute.
        concatenated_attributes = []
        for value, list_ in attributes_to_concat.items():
            concatenated_data = b""
            for d in list_:
                concatenated_data += d.data_type.data
            concatenated_attributes.append(ATTRIBUTE_TYPES[value].parse(len(concatenated_data),
                                                                        concatenated_data))
        # Remove old Attributes that were concatenated.
        for c in concatenated_attributes:
            attributes = [x for x in attributes if x.TYPE != c.TYPE]

        attributes.extend(concatenated_attributes)

        return cls(attributes)

    def find(self, item):
        for attr in self.attributes:
            if item == attr.DESCRIPTION:
                return attr
        return None

    def index(self, item):
        i = 0
        for attr in self.attributes:
            if item == attr.DESCRIPTION:
                break
            i += attr.__len__() + Attribute.HEADER_SIZE
        return i

    def __len__(self):
        total = 0
        for attr in self.attributes:
            total = total + len(attr)
        return total

    def pack(self):
        packed_attributes = bytes()
        for attr in self.attributes:
            packed_attributes += attr.pack()
        return packed_attributes
