"""Radius Attributes"""
# TODO if attributes have requirements e.g. length must be above minimum, can enforce that here.
# TODO could we auto generate this from the radius-types-2.csv available from iana.org?

import struct

from chewie.radius_datatypes import Concat, Enum, Integer, String, Text, Vsa


ATTRIBUTE_TYPES = {}


class Attribute():
    """Parent class for the Attributes."""

    TYPE = None  # e.g. 1
    DATA_TYPE = None  # e.g. Text
    DESCRIPTION = None  # e.g. "User-Name"

    HEADER_SIZE = 1 + 1

    def __init__(self, data_type):
        self.data_type = data_type

    @classmethod
    def create(cls, data):
        """Factory method.
        Args:
            data: object of python type (int, str, bytes, ...)
        Returns:
            Attribute subclass.
        """
        return cls(cls.DATA_TYPE(raw_data=data))  # pylint: disable=not-callable

    @classmethod
    def parse(cls, packed_value):
        """
        Args:
            packed_value (bytes): pre-packed value
        Returns:
            Attribute subclass.
        Raises:
            MessageParseError: if unable to parse the packed_value into the appropriate datatype.
        """
        return cls(cls.DATA_TYPE.parse(packed_value))

    def pack(self):
        """
        Returns:
            packed attribute (including header) bytes
        """
        tl = struct.pack("!BB", self.TYPE, self.full_length())
        v = self.data_type.pack(self.TYPE)
        return tl + v

    def full_length(self):
        """
        Returns:
            length (including header).
        """
        return self.data_type.full_length()


def register_attribute_type(cls):
    """Decoratot to register RADIUS attribute types"""
    ATTRIBUTE_TYPES[cls.TYPE] = cls
    return cls


@register_attribute_type
class UserName(Attribute):
    """User-Name https://tools.ietf.org/html/rfc2865#section-5.1"""
    TYPE = 1
    DATA_TYPE = Text
    DESCRIPTION = "User-Name"


@register_attribute_type
class NASIPAddress(Attribute):
    """Service-Type https://tools.ietf.org/html/rfc2865#section-5.4"""
    TYPE = 4
    DATA_TYPE = String
    DESCRIPTION = "NAS-IP-Address"


@register_attribute_type
class NASPort(Attribute):
    """Service-Type https://tools.ietf.org/html/rfc2865#section-5.5"""
    TYPE = 5
    DATA_TYPE = Integer
    DESCRIPTION = "NAS-Port"


@register_attribute_type
class ServiceType(Attribute):
    """Service-Type https://tools.ietf.org/html/rfc2865#section-5.6"""
    TYPE = 6
    DATA_TYPE = Enum
    DESCRIPTION = "Service-Type"


@register_attribute_type
class FilterId(Attribute):
    """Framed-MTU https://tools.ietf.org/html/rfc2865#section-5.11"""
    TYPE = 11
    DATA_TYPE = Text
    DESCRIPTION = "Filter-Id"


@register_attribute_type
class FramedMTU(Attribute):
    """Framed-MTU https://tools.ietf.org/html/rfc2865#section-5.12"""
    TYPE = 12
    DATA_TYPE = Integer
    DESCRIPTION = "Framed-MTU"


@register_attribute_type
class ReplyMessage(Attribute):
    """Reply-Message https://tools.ietf.org/html/rfc2865#section-5.18"""
    TYPE = 18
    DATA_TYPE = Text
    DESCRIPTION = "Reply-Message"


@register_attribute_type
class State(Attribute):
    """State https://tools.ietf.org/html/rfc2865#section-5.24"""
    TYPE = 24
    DATA_TYPE = String
    DESCRIPTION = "State"

    # TODO length >= 3 https://tools.ietf.org/html/rfc2865#section-5.24


@register_attribute_type
class VendorSpecific(Attribute):
    """Vendor-Specific https://tools.ietf.org/html/rfc2865#section-5.26"""
    TYPE = 26
    DATA_TYPE = Vsa
    DESCRIPTION = "Vendor-Specific"


@register_attribute_type
class SessionTimeout(Attribute):
    """Vendor-Specific https://tools.ietf.org/html/rfc2865#section-5.27"""
    TYPE = 27
    DATA_TYPE = Integer
    DESCRIPTION = "Session-Timeout"


@register_attribute_type
class CalledStationId(Attribute):
    """Called-Station-Id https://tools.ietf.org/html/rfc2865#section-5.30"""
    TYPE = 30
    DATA_TYPE = Text
    DESCRIPTION = "Called-Station-Id"


@register_attribute_type
class CallingStationId(Attribute):
    """Calling-Station-Id https://tools.ietf.org/html/rfc2865#section-5.31"""
    TYPE = 31
    DATA_TYPE = Text
    DESCRIPTION = "Calling-Station-Id"


@register_attribute_type
class NASIdentifier(Attribute):
    """Calling-Station-Id https://tools.ietf.org/html/rfc2865#section-5.32"""
    TYPE = 32
    DATA_TYPE = Text
    DESCRIPTION = "NAS-Identifier"


@register_attribute_type
class AcctSessionId(Attribute):
    """Acct-Session-id (RADIUS Accounting) https://tools.ietf.org/html/rfc2866#section-5.5"""
    TYPE = 44
    DATA_TYPE = Text
    DESCRIPTION = "Acct-Session-Id"


@register_attribute_type
class NASPortType(Attribute):
    """NAS-Port-Type https://tools.ietf.org/html/rfc2865#section-5.41"""
    TYPE = 61
    DATA_TYPE = Enum
    DESCRIPTION = "NAS-Port-Type"


@register_attribute_type
class TunnelType(Attribute):
    """NAS-Port-Type https://tools.ietf.org/html/rfc2868#section-3.1"""
    TYPE = 64
    DATA_TYPE = Enum
    DESCRIPTION = "Tunnel-Type"


@register_attribute_type
class TunnelMediumType(Attribute):
    """NAS-Port-Type https://tools.ietf.org/html/rfc2868#section-3.2"""
    TYPE = 65
    DATA_TYPE = Enum
    DESCRIPTION = "Tunnel-Medium-Type"


@register_attribute_type
class ConnectInfo(Attribute):
    """ConnectInfo (RADIUS Extensions) https://tools.ietf.org/html/rfc2869#section-5.11"""
    TYPE = 77
    DATA_TYPE = Text
    DESCRIPTION = "Connect-Info"


@register_attribute_type
class EAPMessage(Attribute):
    """EAP-Message (RADIUS Extensions) https://tools.ietf.org/html/rfc2869#section-5.13"""
    TYPE = 79
    DATA_TYPE = Concat
    DESCRIPTION = "EAP-Message"

    def pack(self):
        """Concat types need to override AttributeType.pack().
        as Concat.pack() may return multiple packed AVP (each with their own length)"""
        return self.data_type.pack(self.TYPE)


@register_attribute_type
class MessageAuthenticator(Attribute):
    """Message-Authenticator (RADIUS Extensions) https://tools.ietf.org/html/rfc2869#section-5.14"""
    TYPE = 80
    DATA_TYPE = String
    DESCRIPTION = "Message-Authenticator"


@register_attribute_type
class TunnelPrivateGroupID(Attribute):
    """NAS-Port-Type https://tools.ietf.org/html/rfc2868#section-3.6"""
    TYPE = 81
    DATA_TYPE = String
    DESCRIPTION = "Tunnel-Private-Group-ID"
