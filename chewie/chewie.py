"""Entry point for 802.1X speaker.
"""
import random

from chewie.eap import Eap

from chewie.mac_address import MacAddress
from eventlet import sleep, GreenPool
from eventlet.queue import Queue

from chewie import timer_scheduler
from chewie.eap_socket import EapSocket
from chewie.radius_socket import RadiusSocket
from chewie.eap_state_machine import FullEAPStateMachine
from chewie.radius_lifecycle import RadiusLifecycle
from chewie.message_parser import MessageParser, MessagePacker, IdentityMessage
from chewie.event import EventMessageReceived, EventPortStatusChange
from chewie.utils import get_logger, MessageParseError, EapQueueMessage


def unpack_byte_string(byte_string):
    """unpacks a byte string"""
    return "".join("%02x" % x for x in byte_string)


def get_random_id():
    return random.randint(0, 200)


class Chewie:
    """Facilitates EAP supplicant and RADIUS server communication"""
    RADIUS_UDP_PORT = 1812
    PAE_GROUP_ADDRESS = MacAddress.from_string("01:80:C2:00:00:03")

    DEFAULT_PREEMPTIVE_IDENTITY_REQUEST_INTERVAL = 60

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

        self.state_machines = {}  # port_id_str: { mac : state_machine}
        self.port_to_eapol_id = {}  # port_id: last ID used in preemptive identity request.

        self.eap_output_messages = Queue()
        self.radius_output_messages = Queue()

        self.radius_lifecycle = RadiusLifecycle(self.radius_secret, self.chewie_id, self.logger)
        self.timer_scheduler = timer_scheduler.TimerScheduler(self.logger)

        self.eap_socket = None
        self.pool = None
        self.eventlets = None
        self.radius_socket = None
        self.interface_index = None

        self.eventlets = []

    def run(self):
        """setup chewie and start socket eventlet threads"""
        self.logger.info("Starting")
        self.setup_eap_socket()
        self.setup_radius_socket()
        self.start_threads_and_wait()

    def running(self):
        """Used to nicely exit the event loops"""
        return True

    def shutdown(self):
        """kill eventlets and quit"""
        for eventlet in self.eventlets:
            eventlet.kill()

    def start_threads_and_wait(self):
        """Start the thread and wait until they complete (hopefully never)"""
        self.pool = GreenPool()

        self.eventlets.append(self.pool.spawn(self.send_eap_messages))
        self.eventlets.append(self.pool.spawn(self.receive_eap_messages))

        self.eventlets.append(self.pool.spawn(self.send_radius_messages))
        self.eventlets.append(self.pool.spawn(self.receive_radius_messages))

        self.eventlets.append(self.pool.spawn(self.timer_scheduler.run))

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

    def port_down(self, port_id):
        """
        should be called by faucet when port has gone down.
        Args:
            port_id (str): id of port.
        """
        # all chewie needs to do is change its internal state.
        # faucet will remove the acls by itself.
        self.set_port_status(port_id, False)
        self.port_to_eapol_id.pop(port_id, None)

    def port_up(self, port_id):
        """
        should be called by faucet when port has come up
        Args:
            port_id (str): id of port.
        """
        self.set_port_status(port_id, True)

        self.send_preemptive_identity_request(port_id)
        self.timer_scheduler.call_later(self.DEFAULT_PREEMPTIVE_IDENTITY_REQUEST_INTERVAL,
                                        self.send_preemptive_identity_request_if_no_active_on_port,
                                        port_id)

    def send_preemptive_identity_request_if_no_active_on_port(self, port_id):
        """
        If there is no active (in progress, or in state success(2)) supplicant send out the
        preemptive identity request message.
        Args:
            port_id (str):
        """
        state_machines = self.state_machines.get(port_id, [])
        for sm in state_machines.values():
            if sm.state not in [FullEAPStateMachine.LOGOFF, FullEAPStateMachine.LOGOFF2,
                                FullEAPStateMachine.DISABLED, FullEAPStateMachine.NO_STATE,
                                FullEAPStateMachine.FAILURE, FullEAPStateMachine.FAILURE2,
                                FullEAPStateMachine.TIMEOUT_FAILURE,
                                FullEAPStateMachine.TIMEOUT_FAILURE2]:
                break
        else:
            self.send_preemptive_identity_request(port_id)

    def send_preemptive_identity_request(self, port_id):
        """
        Message (EAP Identity Request) that notifies supplicant that port is using 802.1X
        Args:
            port_id (str):

        """
        _id = get_random_id()
        data = IdentityMessage(self.PAE_GROUP_ADDRESS, _id, Eap.REQUEST, "")
        self.port_to_eapol_id[port_id] = _id
        self.eap_output_messages.put_nowait(
            EapQueueMessage(data, self.PAE_GROUP_ADDRESS, MacAddress.from_string(port_id)))

    def set_port_status(self, port_id, status):
        port_id_str = str(port_id)
        if port_id_str not in self.state_machines:
            self.state_machines[port_id_str] = {}

        for src_mac, state_machine in self.state_machines[port_id_str].items():
            event = EventPortStatusChange(status)
            state_machine.event(event)

    def setup_eap_socket(self):
        self.eap_socket = EapSocket(self.interface_name)
        self.eap_socket.setup()

    def setup_radius_socket(self):
        self.radius_socket = RadiusSocket(self.radius_listen_ip,
                                          self.radius_listen_port,
                                          self.radius_server_ip,
                                          self.radius_server_port)
        self.radius_socket.setup()
        self.logger.info("Radius Listening on %s:%d" % (self.radius_listen_ip,
                                                        self.radius_listen_port))

    def send_eap_messages(self):
        """send eap messages to supplicant forever."""
        while self.running():
            sleep(0)
            eap_queue_message = self.eap_output_messages.get()
            self.logger.info("Sending message %s from %s to %s" %
                             (eap_queue_message.message, str(eap_queue_message.port_mac),
                              str(eap_queue_message.src_mac)))
            self.eap_socket.send(MessagePacker.ethernet_pack(eap_queue_message.message,
                                                             eap_queue_message.port_mac,
                                                             eap_queue_message.src_mac))

    def receive_eap_messages(self):
        """receive eap messages from supplicant forever."""
        while self.running():
            sleep(0)
            self.logger.info("waiting for eap.")
            packed_message = self.eap_socket.receive()
            self.logger.info("Received packed_message: %s", str(packed_message))
            try:
                eap, dst_mac = MessageParser.ethernet_parse(packed_message)
            except MessageParseError as exception:
                self.logger.info(
                    "MessageParser.ethernet_parse threw exception.\n"
                    " packed_message: '%s'.\n"
                    " exception: '%s'.",
                    packed_message,
                    exception)
                continue
            self.send_eap_to_state_machine(eap, dst_mac)

    def send_eap_to_state_machine(self, eap, dst_mac):
        """sends an eap message to the state machine"""
        self.logger.info("eap EAP(): %s", eap)
        state_machine = self.get_state_machine(eap.src_mac, dst_mac)
        event = EventMessageReceived(eap, dst_mac)
        state_machine.event(event)

    def send_radius_messages(self):
        """send RADIUS messages to RADIUS Server forever."""
        while self.running():
            sleep(0)
            radius_output_bits = self.radius_output_messages.get()
            packed_message = self.radius_lifecycle.process_outbound(radius_output_bits)
            self.radius_socket.send(packed_message)
            self.logger.info("sent radius message.")

    def receive_radius_messages(self):
        """receive RADIUS messages from RADIUS server forever."""
        while self.running():
            sleep(0)
            self.logger.info("waiting for radius.")
            packed_message = self.radius_socket.receive()
            try:
                radius = MessageParser.radius_parse(packed_message, self.radius_secret,
                                                    self.radius_lifecycle)
            except MessageParseError as exception:
                self.logger.info(
                    "MessageParser.radius_parse threw exception.\n"
                    " packed_message: '%s'.\n"
                    " exception: '%s'.",
                    packed_message,
                    exception)
                continue
            self.send_radius_to_state_machine(radius)
            self.logger.info("Received RADIUS message: %s", radius)

    def send_radius_to_state_machine(self, radius):
        """sends a radius message to the state machine"""
        event = self.radius_lifecycle.build_event_radius_message_received(radius)
        state_machine = self.get_state_machine_from_radius_packet_id(radius.packet_id)
        state_machine.event(event)

    def get_state_machine_from_radius_packet_id(self, packet_id):
        """Gets a FullEAPStateMachine from the RADIUS message packet_id
        Args:
            packet_id (int): id of the received RADIUS message
        Returns:
            FullEAPStateMachine
        """
        return self.get_state_machine(**self.radius_lifecycle.packet_id_to_mac[packet_id])

    def get_state_machine(self, src_mac, port_id):
        """Gets or creates if it does not already exist an FullEAPStateMachine for the src_mac.
        Args:
            src_mac (MacAddress): who's to get.
            port_id (MacAddress): ID of the port where the src_mac is.

        Returns:
            FullEAPStateMachine
        """
        port_id_str = str(port_id)
        src_mac_str = str(src_mac)
        port_state_machines = self.state_machines.get(port_id_str, None)
        if port_state_machines is None:
            self.state_machines[port_id_str] = {}
        state_machine = self.state_machines[port_id_str].get(src_mac_str, None)
        if not state_machine:
            state_machine = FullEAPStateMachine(self.eap_output_messages, self.radius_output_messages, src_mac,
                                                self.timer_scheduler, self.auth_success,
                                                self.auth_failure, self.auth_logoff, self.logger.name)
            state_machine.eap_restart = True
            # TODO what if port is not actually enabled, but then how did they auth?
            state_machine.port_enabled = True
            self.state_machines[port_id_str][src_mac_str] = state_machine
        return state_machine
