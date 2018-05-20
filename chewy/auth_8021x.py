import struct

ETHERNET_HEADER_LENGTH = 6 + 6 + 2

def hwaddr_to_string(hwaddr):
    return ":".join(["%02x" % x for x in hwaddr])

class EthernetHeader(object):
    def __init__(self, dest_mac, src_mac, ethertype):
        self.dest_mac = dest_mac
        self.src_mac = src_mac
        self.ethertype = ethertype

    @classmethod
    def parse(cls, packed_message):
        dest_mac, src_mac, ethertype = struct.unpack("!6s6sH", packed_message[:ETHERNET_HEADER_LENGTH])
        return cls(dest_mac, src_mac, ethertype)

    def __repr__(self):
        return "%s(dest_mac=%s, src_mac=%s, ethertype=0x%04X)" % \
            (self.__class__.__name__, self.dest_mac, self.src_mac, self.ethertype)


AUTH_8021X_HEADER_LENGTH = 1 + 1 + 2

class Auth8021x(object):
    def __init__(self, ethernet_header, version, packet_type, data):
        self.ethernet_header = ethernet_header
        self.version = version
        self.packet_type = packet_type
        self.data = data

    @classmethod
    def parse(cls, packed_message):
        ethernet_header = EthernetHeader.parse(packed_message)
        packed_8021x_message = packed_message[ETHERNET_HEADER_LENGTH:]
        version, packet_type, length = struct.unpack("!BBH", packed_8021x_message[:AUTH_8021X_HEADER_LENGTH])
        data = packed_8021x_message[AUTH_8021X_HEADER_LENGTH:AUTH_8021X_HEADER_LENGTH+length]
        return cls(ethernet_header, version, packet_type, data)

    def __repr__(self):
        return "%s(ethernet_header=%s, version=%s, packet_type=%s, data=%s)" % \
            (self.__class__.__name__, self.ethernet_header, self.version, self.packet_type, self.data)

    def __str__(self):
        return "%s<src=%s, packet_type=%d, data=%s>" % \
            (self.__class__.__name__, hwaddr_to_string(self.ethernet_header.src_mac), self.packet_type, self.data)
