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

    def __init__(self, data):
        self.data = data

    @abc.abstractmethod
    def parse(self, length, packed_value):
        """"""
        return

    @abc.abstractmethod
    def pack(self, attribute_type):
        """"""
        return

    @abc.abstractmethod
    def __len__(self):
        """
        :return: length of the data field, and not total length of the attribute (including the type and length).
        If total is required add 2.
        """
        return


@register_datatype_parser
class Integer(DataType):
    DATA_TYPE_VALUE = 1

    @classmethod
    def parse(cls, length, packed_value):
        if len(packed_value) != 4:
            raise ValueError("RADIUS data type 'integer' length not == 4. Was %d" % len(packed_value))

        return cls(struct.unpack("!I", packed_value)[0])

    def pack(self, attribute_type):
        return struct.pack("!I", self.data)

    def __len__(self):
        return 4


@register_datatype_parser
class Enum(DataType):
    DATA_TYPE_VALUE = 2

    @classmethod
    def parse(cls, length, packed_value):
        if length != 4 or len(packed_value) != 4:
            raise ValueError("RADIUS data type 'enum' length must be 2."
                             "Actual: attribute.length; %d, payload: %d" % (length, len(packed_value)))
        return cls(struct.unpack("!I", packed_value)[0])

    def pack(self, attribute_type):
        return struct.pack("!I", self.data)

    def __len__(self):
        return 4


@register_datatype_parser
class Text(DataType):
    DATA_TYPE_VALUE = 4

    @classmethod
    def parse(cls, length, packed_value):
        if length < 1 \
                or length > DataType.MAX_DATA_LENGTH \
                or len(packed_value) > DataType.MAX_DATA_LENGTH \
                or length != len(packed_value):
            raise ValueError("RADIUS data type 'text' length must not > 253. "
                             "And payload length must not > attribute.length. "
                             "Actual: attribute.length; %d, payload: %d" % (length, len(packed_value)))
        return cls(struct.unpack("!%ds" % length, packed_value)[0].decode('utf-8'))

    def pack(self, attribute_type):
        return struct.pack("!%ds" % len(self.data), self.data.encode('utf-8'))

    def __len__(self):
        return len(self.data)


@register_datatype_parser
class String(DataType):
    # TODO how is this different from Text?? - text us utf8
    DATA_TYPE_VALUE = 5

    @classmethod
    def parse(cls, length, packed_value):
        if length < 1 \
                or length > DataType.MAX_DATA_LENGTH \
                or len(packed_value) > DataType.MAX_DATA_LENGTH \
                or length != len(packed_value):
            raise ValueError("RADIUS data type 'string' length must not > 253. "
                             "And payload length must not > attribute.length. "
                             "Actual: attribute.length; %d, payload: %d" % (length, len(packed_value)))
        return cls(struct.unpack("!%ds" % length, packed_value)[0])

    def pack(self, attribute_type):
        return struct.pack("!%ds" % len(self.data), self.data)

    def __len__(self):
        return len(self.data)


@register_datatype_parser
class Concat(DataType):
    """AttributeTypes that use Concat must override their pack()"""

    DATA_TYPE_VALUE = 6

    @classmethod
    def parse(cls, length, packed_value):
        print('concat buffer', len(packed_value))
        return cls(struct.unpack("!%ds" % length, packed_value)[0])

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

    def __len__(self):
        return self.AVP_HEADER_LEN * \
               (math.ceil(len(self.data) / self.MAX_DATA_LENGTH))\
               + len(self.data) - self.AVP_HEADER_LEN


@register_datatype_parser
class Vsa(DataType):

    DATA_TYPE_VALUE = 14
    VENDOR_ID_LEN = 4

    @classmethod
    def parse(cls, length, packed_value):
        if length < 5:
            raise ValueError("RADIUS Attribute type 'VSA' length must not < 5. "
                             "And payload length must not > attribute.length. "
                             "Actual: attribute.length; %d, payload: %d" % (length, len(packed_value)))
        # TODO Vsa.parse does not separate the vendor-id from the vsa-data
        return cls(struct.unpack("!%ds" % length, packed_value)[0])

    def pack(self, attribute_type):
        return struct.pack("!%ds" % (self.__len__()), self.data)

    def __len__(self):
        return len(self.data)
