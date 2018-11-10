"""Handle the EAP socket
"""
from fcntl import ioctl
import struct

from eventlet.green import socket
from chewie.mac_address import MacAddress

class EapSocket:
    """Handle the EAP socket"""
    SIOCGIFINDEX = 0x8933
    PACKET_MR_PROMISC = 1
    SOL_PACKET = 263
    PACKET_ADD_MEMBERSHIP = 1
    EAP_ADDRESS = MacAddress.from_string("01:80:c2:00:00:03")

    def __init__(self, interface_name):
        self.socket = None
        self.interface_index = None
        self.interface_name = interface_name

    def setup(self):
        """Set up the socket"""
        self.open()
        self.get_interface_index()
        self.set_interface_promiscuous()

    def send(self, data):
        """send on eap socket.
            data (bytes): data to send"""
        self.socket.send(data)

    def receive(self):
        """receive from eap socket"""
        return self.socket.recv(4096)

    def open(self):
        """Setup EAP socket"""
        self.socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x888e)) # pylint: disable=no-member
        self.socket.bind((self.interface_name, 0))

    def get_interface_index(self):
        """Get the interface index of the EAP Socket"""
        # http://man7.org/linux/man-pages/man7/netdevice.7.html
        request = struct.pack('16sI', self.interface_name.encode("utf-8"), 0)
        response = ioctl(self.socket, self.SIOCGIFINDEX, request)
        _ifname, self.interface_index = struct.unpack('16sI', response)

    def set_interface_promiscuous(self):
        """Sets the EAP interface to be able to receive EAP messages"""
        request = struct.pack("IHH8s", self.interface_index, self.PACKET_MR_PROMISC,
                              len(self.EAP_ADDRESS.address), self.EAP_ADDRESS.address)
        self.socket.setsockopt(self.SOL_PACKET, self.PACKET_ADD_MEMBERSHIP, request)
