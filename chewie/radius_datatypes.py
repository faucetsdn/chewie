import abc
import math
import struct


DATA_TYPE_PARSERS = {}


def register_datatype_parser(cls):
    DATA_TYPE_PARSERS[cls.DATA_TYPE_VALUE] = cls.parse
    return cls


class DataType(object):
    DATA_TYPE_VALUE = None
    AVP_HEADER_LEN = 1 + 1
    MAX_DATA_LENGTH = 253
    MIN_DATA_LENGTH = 1

    def __init__(self, data):
        self.data = data

    @abc.abstractmethod
    def parse(self, packed_value):
        """"""
        return

    @abc.abstractmethod
    def pack(self, attribute_type):
        """"""
        return

    @abc.abstractmethod
    def data_length(self):
        """
        :return: length of the data field, and not total length of the attribute (including the type and length).
        If total is required user full_length.
        """
        return 0

    def full_length(self):
        return self.data_length() + self.AVP_HEADER_LEN

    @classmethod
    def is_valid_length(cls, packed_value):
        length = len(packed_value)
        if length < cls.MIN_DATA_LENGTH \
                or length > cls.MAX_DATA_LENGTH \
                or len(packed_value) > cls.MAX_DATA_LENGTH \
                or length != len(packed_value):
            raise ValueError("RADIUS data type '%s' length must be: %d <= actual_length(%d) <= %d"
                             ""
                             % (cls.__name__, cls.MIN_DATA_LENGTH, length, cls.MAX_DATA_LENGTH))


@register_datatype_parser
class Integer(DataType):
    DATA_TYPE_VALUE = 1
    MAX_DATA_LENGTH = 4
    MIN_DATA_LENGTH = 4

    @classmethod
    def parse(cls, packed_value):
        cls.is_valid_length(packed_value)

        return cls(struct.unpack("!I", packed_value)[0])

    def pack(self, attribute_type):
        return struct.pack("!I", self.data)

    def data_length(self):
        return 4


@register_datatype_parser
class Enum(DataType):
    DATA_TYPE_VALUE = 2
    MAX_DATA_LENGTH = 4
    MIN_DATA_LENGTH = 4

    @classmethod
    def parse(cls, packed_value):
        cls.is_valid_length(packed_value)
        return cls(struct.unpack("!I", packed_value)[0])

    def pack(self, attribute_type):
        return struct.pack("!I", self.data)

    def data_length(self):
        return 4


@register_datatype_parser
class Text(DataType):
    DATA_TYPE_VALUE = 4

    @classmethod
    def parse(cls, packed_value):
        cls.is_valid_length(packed_value)
        return cls(struct.unpack("!%ds" % len(packed_value), packed_value)[0].decode('utf-8'))

    def pack(self, attribute_type):
        return struct.pack("!%ds" % len(self.data), self.data.encode('utf-8'))

    def data_length(self):
        return len(self.data)


@register_datatype_parser
class String(DataType):
    # TODO how is this different from Text?? - text is utf8
    DATA_TYPE_VALUE = 5

    @classmethod
    def parse(cls, packed_value):
        cls.is_valid_length(packed_value)
        return cls(struct.unpack("!%ds" % len(packed_value), packed_value)[0])

    def pack(self, attribute_type):
        return struct.pack("!%ds" % len(self.data), self.data)

    def data_length(self):
        return len(self.data)


@register_datatype_parser
class Concat(DataType):
    """AttributeTypes that use Concat must override their pack()"""

    DATA_TYPE_VALUE = 6

    @classmethod
    def parse(cls, packed_value):
        # TODO how do we want to do valid length checking here?
        #
        # Parsing is (generally) for packets coming from the radius server.
        # Packing is (generally) for packets going to the radius server.
        #
        # Therefore we error out if length is too long (you are not allowed to have AVP that are too long)
        return cls(struct.unpack("!%ds" % len(packed_value), packed_value)[0])

    def pack(self, attribute_type):
        packed = bytes()
        mod = len(self.data) % self.MAX_DATA_LENGTH
        if mod == 0:
            mod = self.MAX_DATA_LENGTH
        i = 0
        if len(self.data) > self.MAX_DATA_LENGTH:

            for i in range(int(len(self.data) / self.MAX_DATA_LENGTH)):
                t = struct.pack("!BB253s", attribute_type, self.MAX_DATA_LENGTH + self.AVP_HEADER_LEN,
                                self.data[i * self.MAX_DATA_LENGTH: (i + 1) * self.MAX_DATA_LENGTH])
                packed += t
            i += 1
        packed += struct.pack("!BB%ds" % mod, attribute_type, mod + self.AVP_HEADER_LEN,
                              self.data[i * self.MAX_DATA_LENGTH:])
        return packed

    def full_length(self):
        return self.AVP_HEADER_LEN * \
               (math.ceil(len(self.data) / self.MAX_DATA_LENGTH + 1))\
               + len(self.data) - self.AVP_HEADER_LEN

    def data_length(self):
        return len(self.data)


@register_datatype_parser
class Vsa(DataType):

    DATA_TYPE_VALUE = 14
    VENDOR_ID_LEN = 4
    MIN_DATA_LENGTH = 5

    @classmethod
    def parse(cls, packed_value):
        cls.is_valid_length(packed_value)
        # TODO Vsa.parse does not currently separate the vendor-id from the vsa-data
        # we could do that at some point (e.g. if we wanted to use Vendor-Specific)
        return cls(struct.unpack("!%ds" % len(packed_value), packed_value)[0])

    def pack(self, attribute_type):
        return struct.pack("!%ds" % (self.data_length()), self.data)

    def data_length(self):
        return len(self.data)
