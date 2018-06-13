# TODO if attributes have requirements e.g. length must be above minimum, can enforce that here.
# TODO could we auto generate this from the radius-types-2.csv available from iana.org?

import struct

from chewie.radius_datatypes import Concat, Enum, Integer, String, Text, Vsa, DATA_TYPE_PARSERS


ATTRIBUTE_TYPES = {}


def get_data_type(attribute_type):
    return ATTRIBUTE_TYPES[attribute_type].DATA_TYPE.DATA_TYPE_VALUE


class Attribute(object):

    TYPE = None  # e.g. 1
    DATA_TYPE = None  # e.g. Text
    DESCRIPTION = None  # e.g. User-Name

    HEADER_SIZE = 1 + 1

    def __init__(self, data_type):
        self.data_type = data_type

    @classmethod
    def parse(cls, packed_value):
        data_type = get_data_type(cls.TYPE)
        return cls(DATA_TYPE_PARSERS[data_type](packed_value))

    def pack(self):
        tl = struct.pack("!BB", self.TYPE, self.full_length())
        v = self.data_type.pack(self.TYPE)
        return tl + v

    def full_length(self):
        return self.data_type.full_length()


def register_attribute_type(cls):
    ATTRIBUTE_TYPES[cls.TYPE] = cls
    return cls


@register_attribute_type
class UserName(Attribute):
    TYPE = 1
    DATA_TYPE = Text
    DESCRIPTION = "User-Name"


@register_attribute_type
class ServiceType(Attribute):
    TYPE = 6
    DATA_TYPE = Enum
    DESCRIPTION = "Service-Type"


@register_attribute_type
class FramedMTU(Attribute):
    TYPE = 12
    DATA_TYPE = Integer
    DESCRIPTION = "Framed-MTU"


@register_attribute_type
class ReplyMessage(Attribute):
    TYPE = 18
    DATA_TYPE = Text
    DESCRIPTION = "Reply-Message"


@register_attribute_type
class State(Attribute):
    TYPE = 24
    DATA_TYPE = String
    DESCRIPTION = "State"

    # TODO length >= 3 https://tools.ietf.org/html/rfc2865#section-5.24


@register_attribute_type
class VendorSpecific(Attribute):
    TYPE = 26
    DATA_TYPE = Vsa
    DESCRIPTION = "Vendor-Specific"


@register_attribute_type
class CalledStationId(Attribute):
    TYPE = 30
    DATA_TYPE = Text
    DESCRIPTION = "Called-Station-Id"


@register_attribute_type
class CallingStationId(Attribute):
    TYPE = 31
    DATA_TYPE = Text
    DESCRIPTION = "Calling-Station-Id"


@register_attribute_type
class AcctSessionId(Attribute):
    TYPE = 44
    DATA_TYPE = Text
    DESCRIPTION = "Acct-Session-Id"


@register_attribute_type
class NASPortType(Attribute):
    TYPE = 61
    DATA_TYPE = Enum
    DESCRIPTION = "NAS-Port-Type"


@register_attribute_type
class ConnectInfo(Attribute):
    TYPE = 77
    DATA_TYPE = Text
    DESCRIPTION = "Connect-Info"


@register_attribute_type
class EAPMessage(Attribute):
    TYPE = 79
    DATA_TYPE = Concat
    DESCRIPTION = "EAP-Message"

    def pack(self):
        """Concat types need to override AttributeType.pack().
        as Concat.pack() may return multiple packed AVP (each with their own length)"""
        return self.data_type.pack(self.TYPE)


@register_attribute_type
class MessageAuthenticator(Attribute):
    TYPE = 80
    DATA_TYPE = String
    DESCRIPTION = "Message-Authenticator"
