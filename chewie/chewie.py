from eventlet import sleep, GreenPool
from eventlet.queue import Queue
import eventlet.greenthread as greenthread
import socket
import struct
from hashlib import md5
from fcntl import ioctl
from netils import build_byte_string

from .ethernet_packet import EthernetPacket
from .auth_8021x import Auth8021x
from .eap import Eap, EapIdentity, EapMd5Challenge
from .message_parser import MessageParser, MessagePacker, IdentityMessage, Md5ChallengeMessage
from .mac_address import MacAddress
from .state_machine import StateMachine
from .event import EventMessageReceived

def unpack_byte_string(byte_string):
    return "".join("%02x" % x for x in byte_string)

class Chewie(object):
    SIOCGIFHWADDR = 0x8927
    SIOCGIFINDEX = 0x8933
    PACKET_MR_MULTICAST = 0
    SOL_PACKET = 263
    PACKET_ADD_MEMBERSHIP = 1
    EAP_ADDRESS = build_byte_string("0180c2000003")

    def __init__(self, interface_name, credentials):
        self.interface_name = interface_name
        self.credentials = credentials

    def run(self):
        self.open_socket()
        self.get_interface_info()
        self.build_state_machine()
        self.join_multicast_group()
        #self.run_demo()
        self.start_threads_and_wait()

    def start_threads_and_wait(self):
        print("Starting threads")
        self.pool = GreenPool()
        self.eventlets = []

        self.eventlets.append(self.pool.spawn(self.send_messages))
        self.eventlets.append(self.pool.spawn(self.receive_messages))

        self.pool.waitall()

    def send_messages(self):
        while True:
            sleep(0)
            message = self.state_machine.output_messages.get()
            print("Sending message: %s" % message)
            self.socket.send(MessagePacker.pack(message))

    def receive_messages(self):
        while True:
            sleep(0)
            packed_message = self.socket.recv(4096)
            message = MessageParser.parse(packed_message)
            print("Received message: %s" % message)
            event = EventMessageReceived(message)
            self.state_machine.event(event)

    def run_demo(self):
        self.seed = md5("banana".encode()).digest()
        print("Sending packet")
        self.message_id = 123
        packet = MessagePacker.pack(IdentityMessage(self.interface_address, self.message_id, Eap.REQUEST, ""))
        self.socket.send(packet)
        response = self.socket.recv(4096)
        self.handle_eap_packet(response)
        packet = MessagePacker.pack(Md5ChallengeMessage(self.interface_address, self.message_id, Eap.REQUEST, self.seed, b""))
        self.socket.send(packet)
        response = self.socket.recv(4096)
        self.handle_eap_packet(response)
        # send success to keep it happy
        success = build_byte_string("888e0100000403010004")
        packet = self.EAP_ADDRESS + self.interface_address.address + success
        self.socket.send(packet)

        self.socket.close()

    def handle_eap_packet(self, packed_message):
        print("packed message: %s" % packed_message)
        message = MessageParser.parse(packed_message)
        if isinstance(message, IdentityMessage):
            print("Eap packet type identity")
            print("Identity: %s" % message.identity)
        elif isinstance(message, Md5ChallengeMessage):
            print("Eap packet type md5-challenge")
            print("Response: %s" % unpack_byte_string(message.challenge))
            password="microphone".encode()
            challenge_id_string = struct.pack("B", self.message_id)
            expected_response = md5(challenge_id_string + password + self.seed).digest()
            print("Expected response: %s" % unpack_byte_string(expected_response))
        else:
            print("Unknown message %s" % message)

    def open_socket(self):
        self.socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x888e))
        self.socket.bind((self.interface_name, 0))

    def build_state_machine(self):
        self.state_machine = StateMachine(self.interface_address)

    def get_interface_info(self):
        self.get_interface_address()
        self.get_interface_index()

    def get_interface_address(self):
        # http://man7.org/linux/man-pages/man7/netdevice.7.html
        ifreq = struct.pack('16sH6s', self.interface_name.encode("utf-8"), 0, b"")
        response = ioctl(self.socket, self.SIOCGIFHWADDR, ifreq)
        _interface_name, _address_family, interface_address = struct.unpack('16sH6s', response)
        self.interface_address = MacAddress(interface_address)

    def get_interface_index(self):
        # http://man7.org/linux/man-pages/man7/netdevice.7.html
        ifreq = struct.pack('16sI', self.interface_name.encode("utf-8"), 0)
        response = ioctl(self.socket, self.SIOCGIFINDEX, ifreq)
        _ifname, self.interface_index = struct.unpack('16sI', response)

    def join_multicast_group(self):
        mreq = struct.pack("IHH8s", self.interface_index, self.PACKET_MR_MULTICAST, len(self.EAP_ADDRESS), self.EAP_ADDRESS)
        self.socket.setsockopt(self.SOL_PACKET, self.PACKET_ADD_MEMBERSHIP, mreq)
