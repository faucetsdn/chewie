import struct
from .mac_address import MacAddress

ETHERNET_HEADER_LENGTH = 6 + 6 + 2

class EthernetPacket(object):
    def __init__(self, dst_mac, src_mac, ethertype, data):
        self.dst_mac = MacAddress(dst_mac)
        self.src_mac = MacAddress(src_mac)
        self.ethertype = ethertype
        self.data = data

    @classmethod
    def parse(cls, packed_message):
        dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", packed_message[:ETHERNET_HEADER_LENGTH])
        data = packed_message[ETHERNET_HEADER_LENGTH:]
        return cls(dst_mac, src_mac, ethertype, data)

    def __repr__(self):
        return "%s(dst_mac=%s, src_mac=%s, ethertype=0x%04X)" % \
            (self.__class__.__name__, self.dst_mac, self.src_mac, self.ethertype)