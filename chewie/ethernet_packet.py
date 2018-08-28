import struct
from .mac_address import MacAddress

ETHERNET_HEADER_LENGTH = 6 + 6 + 2

class EthernetPacket(object):
    def __init__(self, dst_mac, src_mac, ethertype, data):
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.ethertype = ethertype
        self.data = data

    @classmethod
    def parse(cls, packed_message):
        dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", packed_message[:ETHERNET_HEADER_LENGTH])
        data = packed_message[ETHERNET_HEADER_LENGTH:]
        return cls(MacAddress(dst_mac), MacAddress(src_mac), ethertype, data)

    def pack(self):
        header = struct.pack("!6s6sH", self.dst_mac.address, self.src_mac.address, self.ethertype)
        return header + self.data

    def __repr__(self):
        return "%s(dst_mac=%s, src_mac=%s, ethertype=0x%04X)" % \
            (self.__class__.__name__, self.dst_mac, self.src_mac, self.ethertype)