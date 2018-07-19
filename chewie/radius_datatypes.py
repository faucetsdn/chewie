import abc
import math
import struct


class DataType(object):
    DATA_TYPE_VALUE = None
    AVP_HEADER_LEN = 1 + 1
    MAX_DATA_LENGTH = 253
    MIN_DATA_LENGTH = 1

    _data = None
    raw_data = None

    def __init__(self, raw_data):
        self.raw_data = raw_data

    @abc.abstractmethod
    def parse(self, packed_value):
        """"""
        return

    @abc.abstractmethod
    def pack(self, attribute_type):
        """"""
        return

    def data(self):
        """

        :return: The python type (int, str, bytes) of the _data.
         This will perform any decoding as required instead of using the unprocessed _data.
        """
        return self._data

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


class Integer(DataType):
    DATA_TYPE_VALUE = 1
    MAX_DATA_LENGTH = 4
    MIN_DATA_LENGTH = 4

    def __init__(self, data=None, raw_data=None):
        super().__init__(raw_data)
        if raw_data:
            try:
                data = raw_data.to_bytes(self.MAX_DATA_LENGTH, "big")
            except OverflowError:
                raise ValueError("Integer must be >= 0  and <= 2^32-1, was %d", raw_data)
        self._data = data

    @classmethod
    def parse(cls, packed_value):
        cls.is_valid_length(packed_value)
        return cls(struct.unpack("!I", packed_value)[0])

    def pack(self, attribute_type):
        return struct.pack("!I", self.raw_data)

    def data_length(self):
        return 4


class Enum(DataType):
    DATA_TYPE_VALUE = 2
    MAX_DATA_LENGTH = 4
    MIN_DATA_LENGTH = 4

    def __init__(self, data=None, raw_data=None):
        super().__init__(raw_data)
        if raw_data:
            try:
                data = raw_data.to_bytes(self.MAX_DATA_LENGTH, "big")
            except OverflowError:
                raise ValueError("Integer must be >= 0  and <= 2^32-1, was %d", raw_data)
        self._data = data


    @classmethod
    def parse(cls, packed_value):
        cls.is_valid_length(packed_value)
        return cls(struct.unpack("!I", packed_value)[0])

    def pack(self, attribute_type):
        return struct.pack("!I", self.raw_data)

    def data_length(self):
        return 4


class Text(DataType):
    DATA_TYPE_VALUE = 4

    def __init__(self, data=None, raw_data=None):
        super().__init__(raw_data)
        if raw_data is not None:
            data = raw_data.encode()
            self.is_valid_length(data)
        self._data = data

    @classmethod
    def parse(cls, packed_value):
        cls.is_valid_length(packed_value)
        return cls(struct.unpack("!%ds" % len(packed_value), packed_value)[0])

    def pack(self, attribute_type):
        return struct.pack("!%ds" % len(self._data), self._data)

    def data(self):
        return self._data.decode("UTF-8")

    def data_length(self):
        return len(self._data)


class String(DataType):
    # how is this different from Text?? - text is utf8
    DATA_TYPE_VALUE = 5

    def __init__(self, data=None, raw_data=None):
        super().__init__(raw_data)
        if raw_data is not None:
            if isinstance(raw_data, bytes):
                data = raw_data
            else:
                data = raw_data.encode()
            self.is_valid_length(data)
        self._data = data

    @classmethod
    def parse(cls, packed_value):
        cls.is_valid_length(packed_value)
        return cls(struct.unpack("!%ds" % len(packed_value), packed_value)[0])

    def pack(self, attribute_type):
        return struct.pack("!%ds" % len(self._data), self._data)

    def data_length(self):
        return len(self._data)


class Concat(DataType):
    """AttributeTypes that use Concat must override their pack()"""

    DATA_TYPE_VALUE = 6

    def __init__(self, data=None, raw_data=None):
        super().__init__(raw_data)
        if raw_data:
            data = bytes.fromhex(raw_data)
            #self.is_valid_length(data)
        self._data = data


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
        mod = len(self._data) % self.MAX_DATA_LENGTH
        if mod == 0:
            mod = self.MAX_DATA_LENGTH
        i = 0
        if len(self._data) > self.MAX_DATA_LENGTH:

            for i in range(int(len(self._data) / self.MAX_DATA_LENGTH)):
                t = struct.pack("!BB253s", attribute_type, self.MAX_DATA_LENGTH + self.AVP_HEADER_LEN,
                                self._data[i * self.MAX_DATA_LENGTH: (i + 1) * self.MAX_DATA_LENGTH])
                packed += t
            i += 1
        packed += struct.pack("!BB%ds" % mod, attribute_type, mod + self.AVP_HEADER_LEN,
                              self._data[i * self.MAX_DATA_LENGTH:])
        return packed

    def full_length(self):
        return self.AVP_HEADER_LEN * \
               (math.ceil(len(self._data) / self.MAX_DATA_LENGTH + 1))\
               + len(self._data) - self.AVP_HEADER_LEN

    def data_length(self):
        return len(self._data)


class Vsa(DataType):

    DATA_TYPE_VALUE = 14
    VENDOR_ID_LEN = 4
    MIN_DATA_LENGTH = 5

    def __init__(self, data=None, raw_data=None):
        super().__init__(raw_data)
        if raw_data:
            data = raw_data
            self.is_valid_length(data)
        self._data = data


    @classmethod
    def parse(cls, packed_value):
        cls.is_valid_length(packed_value)
        # TODO Vsa.parse does not currently separate the vendor-id from the vsa-data
        # we could do that at some point (e.g. if we wanted to use Vendor-Specific)
        return cls(struct.unpack("!%ds" % len(packed_value), packed_value)[0])

    def pack(self, attribute_type):
        return struct.pack("!%ds" % (self.data_length()), self._data)

    def data_length(self):
        return len(self._data)
