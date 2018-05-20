import struct
from netils import build_byte_string

class MacAddress:
    def __init__(self, address):
        self.address = address

    @classmethod
    def from_string(cls, address_string):
        address_bytes = "".join(address_string.split(":"))
        address = build_byte_string(address_bytes)

        return cls(address)

    def __str__(self):
        address_string = ":".join("%02x" % x for x in self.address)
        return address_string

    def __eq__(self, other):
        return self.address == other.address

    def __hash__(self):
        return hash(self.address)

    def __repr__(self):
        return "%s.from_string(\"%s\")" % (self.__class__.__name__, self.__str__())
