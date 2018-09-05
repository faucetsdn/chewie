"""Entry point for 802.1X speaker.
"""
from fcntl import ioctl
import os
import sched
import struct
import time

from eventlet import sleep, GreenPool
from eventlet.green import socket
from eventlet.queue import Queue


from chewie.eap_state_machine import FullEAPStateMachine
from chewie.radius_attributes import EAPMessage, State, CalledStationId, NASPortType
from chewie.message_parser import MessageParser, MessagePacker
from chewie.mac_address import MacAddress
from chewie.event import EventMessageReceived, EventRadiusMessageReceived
from chewie.utils import get_logger


def unpack_byte_string(byte_string):
    """unpacks a byte string"""
    return "".join("%02x" % x for x in byte_string)


class Chewie:
    """Facilitates EAP supplicant and RADIUS server communication"""
    SIOCGIFHWADDR = 0x8927
    SIOCGIFINDEX = 0x8933
    PACKET_MR_MULTICAST = 0
    PACKET_MR_PROMISC = 1
    SOL_PACKET = 263
    PACKET_ADD_MEMBERSHIP = 1
    EAP_ADDRESS = MacAddress.from_string("01:80:c2:00:00:03")
    RADIUS_UDP_PORT = 1812

    def __init__(self, interface_name, logger=None,
                 auth_handler=None, failure_handler=None, logoff_handler=None,
                 radius_server_ip=None, radius_server_port=None, radius_server_secret=None,
                 chewie_id=None):
        self.interface_name = interface_name
        self.logger = get_logger(logger.name + "." + Chewie.__name__)
        self.auth_handler = auth_handler
        self.failure_handler = failure_handler
        self.logoff_handler = logoff_handler

        self.radius_server_ip = radius_server_ip
        self.radius_secret = radius_server_secret
        self.radius_server_port = self.RADIUS_UDP_PORT
        if radius_server_port:
            self.radius_server_port = radius_server_port
        self.radius_listen_ip = "0.0.0.0"
        self.radius_listen_port = 0

        self.chewie_id = "44-44-44-44-44-44:"  # used by the RADIUS Attribute
                                               # 'Called-Station' in Access-Request
        if chewie_id:
            self.chewie_id = chewie_id
        self.extra_radius_request_attributes = self.prepare_extra_radius_attributes()

        self.state_machines = {}  # mac: sm
        self.packet_id_to_mac = {}  # radius_packet_id: mac
        self.packet_id_to_request_authenticator = {}

        self.eap_output_messages = Queue()
        self.radius_output_messages = Queue()

        self.timer_scheduler = sched.scheduler(time.time, sleep)

        self.radius_id = -1
        self.socket = None
        self.pool = None
        self.eventlets = None
        self.radius_socket = None
        self.interface_index = None
        self.interface_address = None

    def run(self):
        """setup chewie and start socket eventlet threads"""
        self.logger.info("Starting")
        self.open_socket()
        self.open_radius_socket()
        self.get_interface_info()
        self.join_multicast_group()
        self.start_threads_and_wait()

    def start_threads_and_wait(self):
        """Start the thread and wait until they complete (hopefully never)"""
        self.pool = GreenPool()
        self.eventlets = []

        self.eventlets.append(self.pool.spawn(self.send_eap_messages))
        self.eventlets.append(self.pool.spawn(self.receive_eap_messages))

        self.eventlets.append(self.pool.spawn(self.send_radius_messages))
        self.eventlets.append(self.pool.spawn(self.receive_radius_messages))

        self.eventlets.append(self.pool.spawn(self.timer_messages))

        self.pool.waitall()

    def auth_success(self, src_mac, port_id):
        """authentication shim between faucet and chewie
        Args:
            src_mac (MacAddress): the mac of the successful supplicant
            port_id (MacAddress): the 'mac' identifier of what switch port the success is on"""
        if self.auth_handler:
            self.auth_handler(src_mac, port_id)

    def auth_failure(self, src_mac, port_id):
        """failure shim between faucet and chewie
                Args:
                    src_mac (MacAddress): the mac of the failed supplicant
                    port_id (MacAddress): the 'mac' identifier of what switch port
                     the failure is on"""
        if self.failure_handler:
            self.failure_handler(src_mac, port_id)

    def auth_logoff(self, src_mac, port_id):
        """logoff shim between faucet and chewie
                Args:
                    src_mac (MacAddress): the mac of the logoff supplicant
                    port_id (MacAddress): the 'mac' identifier of what switch port
                     the logoff is on"""
        if self.logoff_handler:
            self.logoff_handler(src_mac, port_id)

    def send_eap_messages(self):
        """send eap messages to supplicant forever."""
        try:
            while True:
                sleep(0)
                message, src_mac, port_mac = self.eap_output_messages.get()
                self.logger.info("Sending message %s from %s to %s" %
                                 (message, str(port_mac), str(src_mac)))
                self.socket.send(MessagePacker.ethernet_pack(message, port_mac, src_mac))
        except Exception as e:
            self.logger.exception(e)

    def receive_eap_messages(self):
        """receive eap messages from supplicant forever."""
        try:
            while True:
                sleep(0)
                self.logger.info("waiting for eap.")
                packed_message = self.socket.recv(4096)
                self.logger.info("Received packed_message: %s", str(packed_message))

                message, dst_mac = MessageParser.ethernet_parse(packed_message)
                self.logger.info("eap EAP(): %s", message)
                self.logger.info("Received message: %s" % message.__dict__)
                sm = self.get_state_machine(message.src_mac)
                event = EventMessageReceived(message, dst_mac)
                sm.event(event)
        except Exception as e:
            self.logger.exception(e)

    def send_radius_messages(self):
        """send RADIUS messages to RADIUS Server forever."""

        try:
            while True:
                sleep(0)
                eap_message, src_mac, username, state = self.radius_output_messages.get()
                self.logger.info("got eap to send to radius.. mac: %s %s, username: %s",
                                 type(src_mac), src_mac, username)
                state_dict = None
                if state:
                    state_dict = state.__dict__
                self.logger.info("Sending to RADIUS eap message %s with state %s",
                                 eap_message.__dict__, state_dict)
                radius_packet_id = self.get_next_radius_packet_id()
                self.packet_id_to_mac[radius_packet_id] = src_mac
                # message is eap. needs to be wrapped into a radius packet.
                request_authenticator = os.urandom(16)
                self.packet_id_to_request_authenticator[radius_packet_id] = request_authenticator
                data = MessagePacker.radius_pack(eap_message, src_mac, username,
                                                 radius_packet_id, request_authenticator, state,
                                                 self.radius_secret,
                                                 self.extra_radius_request_attributes)
                self.radius_socket.sendto(data, (self.radius_server_ip, self.radius_server_port))
                self.logger.info("sent radius message.")
        except Exception as e:
            self.logger.exception(e)

    def receive_radius_messages(self):
        """receive RADIUS messages from RADIUS server forever."""

        try:
            while True:
                sleep(0)
                self.logger.info("waiting for radius.")
                packed_message = self.radius_socket.recv(4096)
                radius = MessageParser.radius_parse(packed_message, self.radius_secret,
                                                    self.request_authenticator_callback)
                self.logger.info("Received RADIUS message: %s", radius)
                eap_msg = radius.attributes.find(EAPMessage.DESCRIPTION)
                sm = self.get_state_machine_from_radius_packet_id(radius.packet_id)
                eap_msg = eap_msg.data_type.data()
                state = radius.attributes.find(State.DESCRIPTION)
                self.logger.info("radius EAP: %s", eap_msg)
                event = EventRadiusMessageReceived(eap_msg, state)
                sm.event(event)
        except Exception as e:
            self.logger.exception(e)

    def request_authenticator_callback(self, packet_id):
        """Callback to get the RADIUS request Authenticator
        Args:
            packet_id (int):
        Returns:
            the request authenticator sent with the packet_id
            """
        return self.packet_id_to_request_authenticator[packet_id]

    def timer_messages(self):
        """Process timer based events forever."""
        def scheduler_done():
            self.logger.info("scheduler has processed it's last job.")
        try:
            while True:
                # TODO how else could this be made to never end?
                self.timer_scheduler.enter(999999, 99, scheduler_done)
                self.timer_scheduler.run()
                self.logger.info("scheduler completed")
        except Exception as e:
            self.logger.exception(e)

    def open_radius_socket(self):
        """Setup RADIUS Socket"""
        self.radius_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # pylint: disable=no-member
        self.logger.info("Radius Listening on %s:%d" % (self.radius_listen_ip,
                                                        self.radius_listen_port))
        self.radius_socket.bind((self.radius_listen_ip, self.radius_listen_port))

    def open_socket(self):
        """Setup EAP socket"""
        self.socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x888e)) # pylint: disable=no-member
        self.socket.bind((self.interface_name, 0))

    def prepare_extra_radius_attributes(self):
        """Create RADIUS Attirbutes to be sent with every RADIUS request"""
        attr_list = [CalledStationId.create(self.chewie_id), NASPortType.create(15)]
        return attr_list

    def get_interface_info(self):
        """Get information about the EAP socket"""
        self.get_interface_address()
        self.get_interface_index()

    def get_interface_address(self):
        """Get MAC address of the EAP socket."""
        # http://man7.org/linux/man-pages/man7/netdevice.7.html
        ifreq = struct.pack('16sH6s', self.interface_name.encode("utf-8"), 0, b"")
        response = ioctl(self.socket, self.SIOCGIFHWADDR, ifreq)
        _interface_name, _address_family, interface_address = struct.unpack('16sH6s', response)
        self.interface_address = MacAddress(interface_address)

    def get_interface_index(self):
        """Get the interface index of the EAP Socket"""
        # http://man7.org/linux/man-pages/man7/netdevice.7.html
        ifreq = struct.pack('16sI', self.interface_name.encode("utf-8"), 0)
        response = ioctl(self.socket, self.SIOCGIFINDEX, ifreq)
        _ifname, self.interface_index = struct.unpack('16sI', response)

    def join_multicast_group(self):
        """Sets the EAP interface to be able to receive EAP messages"""
        # TODO this works but should blank out the end bytes
        mreq = struct.pack("IHH8s", self.interface_index, self.PACKET_MR_PROMISC,
                           len(self.EAP_ADDRESS.address), self.EAP_ADDRESS.address)
        self.socket.setsockopt(self.SOL_PACKET, self.PACKET_ADD_MEMBERSHIP, mreq)

    def get_state_machine_from_radius_packet_id(self, packet_id):
        """Gets a FullEAPStateMachine from the RADIUS message packet_id
        Args:
            packet_id (int): id of the received RADIUS message
        Returns:
            FullEAPStateMachine
        """
        return self.get_state_machine(self.packet_id_to_mac[packet_id])

    def get_state_machine(self, src_mac):
        """Gets or creates if it does not already exist an FullEAPStateMachine for the src_mac.
        Args:
            src_mac (MACAddress): who's to get.

        Returns:
            FullEAPStateMachine
        """
        sm = self.state_machines.get(src_mac, None)
        if not sm:
            sm = FullEAPStateMachine(self.eap_output_messages, self.radius_output_messages, src_mac,
                                     self.timer_scheduler, self.auth_success,
                                     self.auth_failure, self.auth_logoff, self.logger.name)
            sm.eapRestart = True
            # TODO what if port is not actually enabled, but then how did they auth?
            sm.portEnabled = True
            self.state_machines[src_mac] = sm
        return sm

    def get_next_radius_packet_id(self):
        """Calulate the next RADIUS Packet ID
        Returns:
            int
        """
        self.radius_id += 1
        if self.radius_id > 255:
            self.radius_id = 0
        return self.radius_id
