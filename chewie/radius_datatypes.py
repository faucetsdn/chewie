"""Radius Attribute Datatypes"""
import ipaddress
import math
import struct

import chewie.message_parser


# TODO would like to clean up the interface for creating/initing,
# so that you can give it multiple python objects (e.g. ipaddr prefix),
# and be able to access them later by name, instead of bit bashing the bytes_data.
# but it wouldnt really be used atm.
# perhaps create(description, {vendor-id: 12345, vendor-data: "abcdefg"})


class DataType:
    """Parent datatype class, subclass should provide implementation for abstractmethods.
    May """
    DATA_TYPE_VALUE = None
    AVP_HEADER_LEN = 1 + 1
    MAX_DATA_LENGTH = 253
    MIN_DATA_LENGTH = 1

    bytes_data = None  # bytes version of raw_data
    DESCRIPTION = None

    TYPE =  None

    def __init__(self, description=None, _type=None, bytes_data=None):
        self.DESCRIPTION = description
        self.bytes_data = bytes_data
        self.TYPE = _type

    def parse(self, packed_value, _type):
        """"""
        return

    def pack(self):
        """"""
        return

    def data(self):
        """Subclass should override this as needed.
        Returns:
             The python type (int, str, bytes) of the bytes_data.
         This will perform any decoding as required instead of using the unprocessed bytes_data.
        """
        return self.bytes_data

    def data_length(self):
        """
        Returns:
             length of the data field, and not total length of the attribute (including the
         type and length).
        If total is required use full_length.
        """
        return 0

    def full_length(self):
        """
        Returns:
            Length of the whole field include the header (type and length)
        """
        return self.data_length() + self.AVP_HEADER_LEN

    @classmethod
    def is_valid_length(cls, packed_value):
        length = len(packed_value)
        if length < cls.MIN_DATA_LENGTH \
                or length > cls.MAX_DATA_LENGTH \
                or len(packed_value) > cls.MAX_DATA_LENGTH \
                or length != len(packed_value):
            raise ValueError("RADIUS data type '%s' length must be: %d <= actual_length(%d) <= %d"
                             % (cls.__name__, cls.MIN_DATA_LENGTH, length, cls.MAX_DATA_LENGTH))


class Integer(DataType):
    """https://tools.ietf.org/html/rfc8044#section-3.1"""
    DATA_TYPE_VALUE = 1
    MAX_DATA_LENGTH = 4
    MIN_DATA_LENGTH = 4

    def create(self, bytes_data=None, raw_data=None):
        if raw_data:
            try:
                bytes_data = raw_data.to_bytes(self.MAX_DATA_LENGTH, "big")
            except OverflowError:
                raise ValueError("Integer must be >= 0  and <= 2^32-1, was %d" % raw_data)
        return self.__class__(description=self.DESCRIPTION, bytes_data=bytes_data, _type=self.TYPE)

    @classmethod
    def parse(cls, packed_value, _type):
        cls.is_valid_length(packed_value)
        return cls(bytes_data=struct.unpack("!4s", packed_value)[0], _type=_type)

    def pack(self):
        tl = struct.pack("!BB", self.TYPE, self.full_length())
        v = struct.pack("!4s", self.bytes_data)
        return tl + v

    def data(self):
        return int.from_bytes(self.bytes_data, 'big')  # pytype: disable=attribute-error

    def data_length(self):
        return 4


class Enum(DataType):
    """https://tools.ietf.org/html/rfc8044#section-3.2"""
    DATA_TYPE_VALUE = 2
    MAX_DATA_LENGTH = 4
    MIN_DATA_LENGTH = 4

    def create(self, bytes_data=None, raw_data=None):
        if raw_data:
            try:
                bytes_data = raw_data.to_bytes(self.MAX_DATA_LENGTH, "big")
            except OverflowError:
                raise ValueError("Integer must be >= 0  and <= 2^32-1, was %d" % raw_data)
        return self.__class__(description=self.DESCRIPTION, bytes_data=bytes_data, _type=self.TYPE)

    @classmethod
    def parse(cls, packed_value, _type):
        cls.is_valid_length(packed_value)
        return cls(bytes_data=struct.unpack("!4s", packed_value)[0], _type=_type)

    def pack(self):
        tl = struct.pack("!BB", self.TYPE, self.full_length())
        v = struct.pack("!4s", self.bytes_data)
        return tl + v

    def data(self):
        return int.from_bytes(self.bytes_data, 'big')  # pytype: disable=attribute-error

    def data_length(self):
        return 4


class Time(DataType):
    """https://tools.ietf.org/html/rfc8044#section-3.3"""
    DATA_TYPE_VALUE = 3
    MAX_DATA_LENGTH = 4
    MIN_DATA_LENGTH = 4

    def create(self, bytes_data=None, raw_data=None):
        if raw_data:
            bytes_data = struct.pack('!f', raw_data)
        return self.__class__(description=self.DESCRIPTION, bytes_data=bytes_data, _type=self.TYPE)

    @classmethod
    def parse(cls, packed_value, _type):
        cls.is_valid_length(packed_value)
        return cls(bytes_data=struct.unpack("!4s", packed_value)[0], _type=_type)

    def pack(self):
        tl = struct.pack("!BB", self.TYPE, self.full_length())
        v = struct.pack("!4s", self.bytes_data)
        return tl + v

    def data(self):
        return struct.unpack('!f', self.bytes_data)[0]

    def data_length(self):
        return 4


class Text(DataType):
    """https://tools.ietf.org/html/rfc8044#section-3.4"""
    DATA_TYPE_VALUE = 4

    def create(self, bytes_data=None, raw_data=None):
        if raw_data is not None:
            bytes_data = raw_data.encode()
            self.is_valid_length(bytes_data)
        return self.__class__(description=self.DESCRIPTION, bytes_data=bytes_data, _type=self.TYPE)

    @classmethod
    def parse(cls, packed_value, _type):
        cls.is_valid_length(packed_value)
        return cls(bytes_data=struct.unpack("!%ds" % len(packed_value),
                                            packed_value)[0], _type=_type)

    def pack(self):
        tl = struct.pack("!BB", self.TYPE, self.full_length())
        v = struct.pack("!%ds" % len(self.bytes_data), self.bytes_data)
        return tl + v

    def data(self):
        return self.bytes_data.decode("UTF-8")

    def data_length(self):
        return len(self.bytes_data)


class String(DataType):
    # how is this different from Text?? - text is utf8
    DATA_TYPE_VALUE = 5

    def create(self, bytes_data=None, raw_data=None):
        if raw_data is not None:
            if isinstance(raw_data, bytes):
                bytes_data = raw_data
            else:
                bytes_data = raw_data.encode()
            self.is_valid_length(bytes_data)
        return self.__class__(description=self.DESCRIPTION, bytes_data=bytes_data, _type=self.TYPE)

    @classmethod
    def parse(cls, packed_value, _type):
        cls.is_valid_length(packed_value)
        return cls(bytes_data=struct.unpack("!%ds" % len(packed_value),
                                            packed_value)[0], _type=_type)

    def pack(self):
        tl = struct.pack("!BB", self.TYPE, self.full_length())
        v = struct.pack("!%ds" % len(self.bytes_data), self.bytes_data)
        return tl + v

    def data_length(self):
        return len(self.bytes_data)


class Concat(DataType):
    """AttributeTypes that use Concat must override their pack()"""

    DATA_TYPE_VALUE = 6

    def create(self, bytes_data=None, raw_data=None):
        if raw_data:
            if isinstance(raw_data, chewie.message_parser.EapMessage):
                bytes_data = chewie.message_parser.MessagePacker.eap_pack(raw_data)[2]
            else:
                bytes_data = bytes.fromhex(raw_data)
            # self.is_valid_length(data)
        # self.bytes_data = bytes_data
        return self.__class__(description=self.DESCRIPTION, bytes_data=bytes_data, _type=self.TYPE)

    @classmethod
    def parse(cls, packed_value, _type):
        # TODO how do we want to do valid length checking here?
        #
        # Parsing is (generally) for packets coming from the radius server.
        # Packing is (generally) for packets going to the radius server.
        #
        # Therefore we error out if length is too long
        #  (you are not allowed to have AVP that are too long)
        return cls(bytes_data=struct.unpack("!%ds" % len(packed_value),
                                            packed_value)[0], _type=_type)

    def pack(self):
        packed = bytes()
        mod = len(self.bytes_data) % self.MAX_DATA_LENGTH
        if mod == 0:
            mod = self.MAX_DATA_LENGTH
        i = 0
        if len(self.bytes_data) > self.MAX_DATA_LENGTH:

            for i in range(int(len(self.bytes_data) / self.MAX_DATA_LENGTH)):
                t = struct.pack("!BB253s", self.TYPE,
                                self.MAX_DATA_LENGTH + self.AVP_HEADER_LEN,
                                self.bytes_data[i * self.MAX_DATA_LENGTH:
                                                (i + 1) * self.MAX_DATA_LENGTH])
                packed += t
            i += 1
        packed += struct.pack("!BB%ds" % mod, self.TYPE, mod + self.AVP_HEADER_LEN,
                              self.bytes_data[i * self.MAX_DATA_LENGTH:])
        return packed

    def data(self):
        return chewie.message_parser.MessageParser.eap_parse(self.bytes_data, None)

    def full_length(self):
        return self.AVP_HEADER_LEN * \
               (math.ceil(len(self.bytes_data) / self.MAX_DATA_LENGTH + 1))\
               + len(self.bytes_data) - self.AVP_HEADER_LEN

    def data_length(self):
        return len(self.bytes_data)


class Ifid(DataType):
    """The "ifid" data type encodes an Interface-Id as an 8-octet IPv6
   Interface Identifier in network byte order.
    https://tools.ietf.org/html/rfc8044#section-3.7"""
    DATA_TYPE_VALUE = 7
    MAX_DATA_LENGTH = 8
    MIN_DATA_LENGTH = 8

    def create(self, bytes_data=None, raw_data=None):
        if raw_data:
            raise ValueError("Ifid does not support creating with raw_data yet. use bytes_data")
        return self.__class__(description=self.DESCRIPTION, bytes_data=bytes_data, _type=self.TYPE)

    @classmethod
    def parse(cls, packed_value, _type):
        cls.is_valid_length(packed_value)
        return cls(bytes_data=struct.unpack("!8s", packed_value)[0], _type=_type)

    def pack(self):
        tl = struct.pack("!BB", self.TYPE, self.full_length())
        v = struct.pack("!8s", self.bytes_data)
        return tl + v

    def data(self):
        return int.from_bytes(self.bytes_data, 'big')  # pytype: disable=attribute-error

    def data_length(self):
        return 8


class Ipv4addr(DataType):
    """
    https://tools.ietf.org/html/rfc8044#section-3.8"""
    DATA_TYPE_VALUE = 8
    MAX_DATA_LENGTH = 4
    MIN_DATA_LENGTH = 4

    def create(self, bytes_data=None, raw_data=None):
        if raw_data:
            bytes_data = ipaddress.v4_int_to_packed(int(ipaddress.IPv4Address(raw_data)))
        return self.__class__(description=self.DESCRIPTION, bytes_data=bytes_data, _type=self.TYPE)

    @classmethod
    def parse(cls, packed_value, _type):
        cls.is_valid_length(packed_value)
        return cls(bytes_data=struct.unpack("!4s", packed_value)[0], _type=_type)

    def pack(self):
        tl = struct.pack("!BB", self.TYPE, self.full_length())
        v = struct.pack("!4s", self.bytes_data)
        return tl + v

    def data(self):
        return str(ipaddress.IPv4Address(self.bytes_data))  # pytype: disable=attribute-error

    def data_length(self):
        return 4


class Ipv6addr(DataType):
    """
    https://tools.ietf.org/html/rfc8044#section-3.9"""
    DATA_TYPE_VALUE = 9
    MAX_DATA_LENGTH = 16
    MIN_DATA_LENGTH = 16

    def create(self, bytes_data=None, raw_data=None):
        if raw_data:
            bytes_data = ipaddress.v6_int_to_packed(int(ipaddress.IPv6Address(raw_data)))
        return self.__class__(description=self.DESCRIPTION, bytes_data=bytes_data, _type=self.TYPE)

    @classmethod
    def parse(cls, packed_value, _type):
        cls.is_valid_length(packed_value)
        return cls(bytes_data=struct.unpack("!16s", packed_value)[0], _type=_type)

    def pack(self):
        tl = struct.pack("!BB", self.TYPE, self.full_length())
        v = struct.pack("!16s", self.bytes_data)
        return tl + v

    def data(self):
        return str(ipaddress.IPv6Address(self.bytes_data))  # pytype: disable=attribute-error

    def data_length(self):
        return 16


class Ipv6prefix(DataType):
    """
    https://tools.ietf.org/html/rfc8044#section-3.10"""
    DATA_TYPE_VALUE = 10
    MAX_DATA_LENGTH = 18
    MIN_DATA_LENGTH = 2

    def create(self, bytes_data=None, raw_data=None):
        if raw_data:
            raise NotImplementedError('IPv6prefix does not support create with raw_data yet.')
        return self.__class__(description=self.DESCRIPTION, bytes_data=bytes_data, _type=self.TYPE)

    @classmethod
    def parse(cls, packed_value, _type):
        cls.is_valid_length(packed_value)
        size = len(packed_value) - 2
        reserved, prefix_length, prefix = struct.unpack("!BB%ds" % size, packed_value)
        prefix = int.from_bytes(prefix, byteorder='big')  # pytype: disable=attribute-error
        if reserved != 0:
            raise ValueError('Ipv6prefix reserved must be 0. Cannot parse')
        if prefix_length > 128:
            raise ValueError('Ipv6prefix prefix_length must be at least 0 and no larger than 128. Cannot parse')

        if prefix_length < size * 8:
            # check zeroed
            x = 0
            for _ in range(size * 8 - prefix_length):
                x = (x << 1) + 1

            if x & prefix != 0:
                raise ValueError('Ipv6 prefix has length < 128. and bits outside of prefix length not zero')
        # TODO at some point it would be nice if we could extract the prefix from this datatype.
        return cls(bytes_data=packed_value, _type=_type)

    def pack(self):
        tl = struct.pack("!BB", self.TYPE, self.full_length())
        v = struct.pack("!%ds" % len(self.bytes_data), self.bytes_data)
        return tl + v

    def data(self):
        return str(ipaddress.IPv6Address(self.bytes_data))  # pytype: disable=attribute-error

    def data_length(self):
        return len(self.bytes_data)


class Ipv4prefix(DataType):
    """
    https://tools.ietf.org/html/rfc8044#section-3.10"""
    DATA_TYPE_VALUE = 11
    MAX_DATA_LENGTH = 6
    MIN_DATA_LENGTH = 6

    # TODO at some point it would be nice if we could extract the prefix from this datatype.
    # TODO if address is all 0s then the prefix-length must be set to 32.

    def create(self, bytes_data=None, raw_data=None):
        if raw_data:
            raise NotImplementedError('IPv4prefix does not support create with raw_data yet.')
        return self.__class__(description=self.DESCRIPTION, bytes_data=bytes_data, _type=self.TYPE)

    @classmethod
    def parse(cls, packed_value, _type):
        cls.is_valid_length(packed_value)
        reserved, prefix_length, prefix = struct.unpack("!BB4s", packed_value)
        prefix = int.from_bytes(prefix, byteorder='big')  # pytype: disable=attribute-error
        if reserved != 0:
            raise ValueError('Ipv4prefix reserved must be 0. Cannot parse')
        if prefix_length > 32:
            raise ValueError('Ipv4prefix prefix_length must be at least 0 and no larger than 32. Cannot parse')

        if prefix_length < 32:
            # check zeroed
            x = 0
            for _ in range(32 - prefix_length):
                x = (x << 1) + 1

            if x & prefix != 0:
                raise ValueError('Ipv4 prefix has length < 128. and bits outside of prefix length not zero')

        return cls(bytes_data=packed_value, _type=_type)

    def pack(self):
        tl = struct.pack("!BB", self.TYPE, self.full_length())
        v = struct.pack("!%ds" % len(self.bytes_data), self.bytes_data)
        return tl + v

    def data(self):
        return self.bytes_data

    def data_length(self):
        return len(self.bytes_data)


class Vsa(DataType):

    DATA_TYPE_VALUE = 14
    VENDOR_ID_LEN = 4
    MIN_DATA_LENGTH = 5

    def create(self, bytes_data=None, raw_data=None):
        if raw_data:
            bytes_data = raw_data
            self.is_valid_length(bytes_data)
        return self.__class__(description=self.DESCRIPTION, bytes_data=bytes_data, _type=self.TYPE)

    @classmethod
    def parse(cls, packed_value, _type):
        cls.is_valid_length(packed_value)
        # TODO Vsa.parse does not currently separate the vendor-id from the vsa-data
        # we could do that at some point (e.g. if we wanted to use Vendor-Specific)
        return cls(bytes_data=struct.unpack("!%ds" % len(packed_value),
                                            packed_value)[0], _type=_type)

    def pack(self):
        tl = struct.pack("!BB", self.TYPE, self.full_length())
        v = struct.pack("!%ds" % (self.data_length()), self.bytes_data)
        return tl + v

    def data_length(self):
        return len(self.bytes_data)
