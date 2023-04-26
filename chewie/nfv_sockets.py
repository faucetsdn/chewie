"""Supplicant-Facing Sockets"""

import struct
from abc import ABC, abstractmethod
from fcntl import ioctl
from eventlet.green import socket

from chewie.mac_address import MacAddress
from chewie.utils import get_logger


class PromiscuousSocket(ABC):
    """Abstract Raw Socket in Promiscuous Mode"""

    SIOCGIFINDEX = 0x8933
    PACKET_MR_PROMISC = 1
    SOL_PACKET = 263
    PACKET_ADD_MEMBERSHIP = 1
    EAP_ADDRESS = MacAddress.from_string("01:80:c2:00:00:03")

    @abstractmethod
    def send(self, data):  # pylint: disable=missing-docstring
        pass

    @abstractmethod
    def receive(self):  # pylint: disable=missing-docstring
        pass

    @abstractmethod
    def setup(self):  # pylint: disable=missing-docstring
        pass

    def __init__(self, interface_name, log_prefix):
        self.socket = None
        self.interface_index = None
        self.interface_name = interface_name
        self.logger = get_logger(log_prefix)

    def _setup(self, socket_filter):
        """Set up the socket"""
        self.logger.info("Setting up socket on interface: %s", self.interface_name)
        try:
            self.open(socket_filter)
            self.get_interface_index()
            self.set_interface_promiscuous()
        except socket.error as err:
            self.logger.error("Unable to setup socket: %s", str(err))
            raise err

    def open(self, socket_filter):
        """Setup EAP socket"""
        self.socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket_filter)
        self.socket.bind((self.interface_name, 0))

    def get_interface_index(self):
        """Get the interface index of the EAP Socket"""
        # http://man7.org/linux/man-pages/man7/netdevice.7.html
        request = struct.pack("16sI", self.interface_name.encode("utf-8"), 0)
        response = ioctl(self.socket, self.SIOCGIFINDEX, request)
        _ifname, self.interface_index = struct.unpack("16sI", response)

    def set_interface_promiscuous(self):
        """Sets the EAP interface to be able to receive EAP messages"""
        request = struct.pack(
            "IHH8s",
            self.interface_index,
            self.PACKET_MR_PROMISC,
            len(self.EAP_ADDRESS.address),
            self.EAP_ADDRESS.address,
        )
        self.socket.setsockopt(self.SOL_PACKET, self.PACKET_ADD_MEMBERSHIP, request)


class EapSocket(PromiscuousSocket):
    """Handle the EAP socket"""

    def setup(self):
        """Set up the socket"""
        self._setup(socket.htons(0x888E))

    def send(self, data):
        """send on eap socket.
        data (bytes): data to send"""
        self.socket.send(data)

    def receive(self):
        """receive from eap socket"""
        return self.socket.recv(4096)


class MabSocket(PromiscuousSocket):
    """Handle the Mab socket for DHCP Requests"""

    IP_ETHERTYPE = 0x0800
    DHCP_UDP_SRC = 68
    DHCP_UDP_DST = 67
    UDP_IPTYPE = b"\x11"

    def setup(self):
        """Set up the socket"""
        self._setup(socket.htons(self.IP_ETHERTYPE))

    def send(self, data):
        """Not Implemented -- This socket is purely for Listening"""
        raise NotImplementedError("Attempted to send data down the activity socket")

    def receive(self):
        """Receive activity from supplicant-facing socket"""
        # Skip all packets that are not DHCP requests
        while True:
            ret_val = self.socket.recv(4096)

            if ret_val[23:24] == self.UDP_IPTYPE:
                src_port = struct.unpack(">H", ret_val[34:36])[0]
                dst_port = struct.unpack(">H", ret_val[36:38])[0]

                if src_port == self.DHCP_UDP_SRC and dst_port == self.DHCP_UDP_DST:
                    return ret_val
