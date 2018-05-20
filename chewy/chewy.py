import socket
import struct
from hashlib import md5
from fcntl import ioctl
from netils import build_byte_string

from .auth_8021x import Auth8021x
from .eap import Eap, EapIdentity, EapMd5Challenge

def unpack_byte_string(byte_string):
    return "".join("%02x" % x for x in byte_string)

class Chewy(object):
    SIOCGIFHWADDR = 0x8927
    SIOCGIFINDEX = 0x8933
    PACKET_MR_MULTICAST = 0
    SOL_PACKET = 263
    PACKET_ADD_MEMBERSHIP = 1
    EAP_ADDRESS = build_byte_string("0180c2000003")

    def __init__(self, interface_name):
        self.interface_name = interface_name

    def run(self):
        self.open_socket()
        self.get_interface_info()
        self.join_multicast_group()
        self.run_demo()

    def run_demo(self):
        print("Sending packet")
        identity_request = build_byte_string("888e010000050101000501")
        packet = self.EAP_ADDRESS + self.interface_address + identity_request
        self.socket.send(packet)
        response = self.socket.recv(4096)
        self.handle_eap_packet(response)
        challenge = build_byte_string("888e01000016010100160410824788d693e2adac6ce15641418228cf")
        packet = self.EAP_ADDRESS + self.interface_address + challenge
        self.socket.send(packet)
        response = self.socket.recv(4096)
        self.handle_eap_packet(response)
        # send success to keep it happy
        success = build_byte_string("888e0100000403010004")
        packet = self.EAP_ADDRESS + self.interface_address + success
        self.socket.send(packet)

        self.socket.close()

    def handle_eap_packet(self, packed_message):
        auth_8021x = Auth8021x.parse(packed_message)
        print("packed message: %s" % packed_message)
        eap = Eap.parse(auth_8021x.data)
        print("data: %s" % auth_8021x.data)
        if eap.packet_type == 1:
            print("Eap packet type identity")
            identity = EapIdentity.parse(eap.data)
            print("Identity: %s" % identity.identity)
        elif eap.packet_type == 4:
            print("Eap packet type md5-challenge")
            challenge = EapMd5Challenge.parse(eap.data)
            print("Response: %s" % unpack_byte_string(challenge.value))
            challenge_salt = build_byte_string("824788d693e2adac6ce15641418228cf")
            password="microphone".encode()
            challenge_id=1
            challenge_id_string = struct.pack("B", challenge_id)
            expected_response = md5(challenge_id_string + password + challenge_salt).digest()
            print("Expected response: %s" % unpack_byte_string(expected_response))
        else:
            print("Unknown Eap packet type: %d" % eap.packet_type)

    def open_socket(self):
        self.socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x888e))
        self.socket.bind((self.interface_name, 0))

    def get_interface_info(self):
        self.get_interface_address()
        self.get_interface_index()

    def get_interface_address(self):
        # http://man7.org/linux/man-pages/man7/netdevice.7.html
        ifreq = struct.pack('16sH6s', self.interface_name.encode("utf-8"), 0, b"")
        response = ioctl(self.socket, self.SIOCGIFHWADDR, ifreq)
        _interface_name, _address_family, self.interface_address = struct.unpack('16sH6s', response)

    def get_interface_index(self):
        # http://man7.org/linux/man-pages/man7/netdevice.7.html
        ifreq = struct.pack('16sI', self.interface_name.encode("utf-8"), 0)
        response = ioctl(self.socket, self.SIOCGIFINDEX, ifreq)
        _ifname, self.interface_index = struct.unpack('16sI', response)


    def join_multicast_group(self):
        mreq = struct.pack("IHH8s", self.interface_index, self.PACKET_MR_MULTICAST, len(self.EAP_ADDRESS), self.EAP_ADDRESS)
        self.socket.setsockopt(self.SOL_PACKET, self.PACKET_ADD_MEMBERSHIP, mreq)
