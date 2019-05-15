"""Handle activity that is not EAP on the same EAP interface"""

import struct
from fcntl import ioctl
from eventlet.green import socket

from chewie.mac_address import MacAddress

class ActivitySocket:
    """Handle the RADIUS socket"""
    SIOCGIFINDEX = 0x8933
    PACKET_MR_PROMISC = 1
    IP_ETHERTYPE = 0x0800
    SOL_PACKET = 263
    PACKET_ADD_MEMBERSHIP = 1

    DHCP_UDP_SRC = 68
    DHCP_UDP_DST = 67
    UDP_IPTYPE = b'\x11'
    EAP_ADDRESS = MacAddress.from_string("01:80:c2:00:00:03")

    def __init__(self, interface_name):
        self.socket = None
        self.interface_name = interface_name
        self.interface_index = None

    def setup(self):
        """Set up the socket"""
        self.open()
        self.get_interface_index()
        self.set_interface_promiscuous()

    def send(self, data):
        """Not Implemented -- This socket is purely for Listening"""
        raise NotImplementedError('Attempted to send data down the activity socket')

    def receive(self):
        """Receive activity from supplicant-facing socket"""
        # Skip all packets that are not DHCP requests
        while True:
            ret_val = self.socket.recv(4096)

            if ret_val[23:24] == self.UDP_IPTYPE:
                src_port = struct.unpack('>H', ret_val[34:36])[0]
                dst_port = struct.unpack('>H', ret_val[36:38])[0]

                if src_port == self.DHCP_UDP_SRC and dst_port == self.DHCP_UDP_DST:
                    return ret_val

    def open(self):
        """Listen on the Socket for any form of Eth() / IP() frames """
        self.socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,  # pylint: disable=no-member
                                    socket.htons(self.IP_ETHERTYPE))    # pylint: disable=no-member
        self.socket.bind((self.interface_name, 0))

    def get_interface_index(self):
        """Get the interface index of the Socket"""
        # http://man7.org/linux/man-pages/man7/netdevice.7.html
        request = struct.pack('16sI', self.interface_name.encode("utf-8"), 0)
        response = ioctl(self.socket, self.SIOCGIFINDEX, request)
        _ifname, self.interface_index = struct.unpack('16sI', response)

    def set_interface_promiscuous(self):
        """Sets the activity interface to be able to receive messages with port_id in mac_dst"""
        request = struct.pack("IHH8s", self.interface_index, self.PACKET_MR_PROMISC,
                              len(self.EAP_ADDRESS.address), self.EAP_ADDRESS.address)

        self.socket.setsockopt(self.SOL_PACKET, self.PACKET_ADD_MEMBERSHIP, request)
