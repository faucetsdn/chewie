import logging
import tempfile
import unittest
from queue import Queue

from chewie.ethernet_packet import EthernetPacket
from chewie.event import EventMessageReceived, EventRadiusMessageReceived
from chewie.mac_address import MacAddress
from chewie.radius import RadiusAccessReject, RadiusAccessAccept
from chewie.state_machines.mab_state_machine import MacAuthenticationBypassStateMachine


# TODO Remove and create a 'test state machine' class
def check_counters(_func=None, *,
                   expected_auth_counter=0, expected_failure_counter=0):
    """Decorator to check the handlers have been called the
     correct number of times at the end of each test"""

    def decorator_check_counters(func):
        def wrapper(self):
            start_auth_counter = self.auth_counter
            start_failure_counter = self.failure_counter
            ret = func(self)
            self.assertEqual(self.auth_counter,
                             start_auth_counter + expected_auth_counter)
            self.assertEqual(self.failure_counter,
                             start_failure_counter + expected_failure_counter)
            return ret

        return wrapper

    if _func is None:
        return decorator_check_counters

    return decorator_check_counters(_func)


class MABStateMachineTest(unittest.TestCase):
    PORT_ID_MAC = MacAddress.from_string("00:00:00:00:00:01")

    def setUp(self):
        # Build the state machine
        logger = logging.getLogger()
        logger.level = logging.DEBUG
        self.log_file = tempfile.NamedTemporaryFile()
        logger.addHandler(logging.FileHandler(self.log_file.name))

        self.radius_output_queue = Queue()
        self.timer_scheduler = None
        self.src_mac = MacAddress.from_string("00:12:34:56:78:90")
        log_prefix = "chewie.SM - port: %s, client: %s" % (self.src_mac, self.PORT_ID_MAC)

        self.sm = MacAuthenticationBypassStateMachine(self.radius_output_queue,
                                                      self.src_mac, self.timer_scheduler,
                                                      self.auth_handler, self.failure_handler,
                                                      log_prefix)

        self.auth_counter = 0
        self.failure_counter = 0

    # pylint: disable=unused-argument
    def auth_handler(self, client_mac, port_id_mac, timer, *arg, **kwargs):
        self.auth_counter += 1
        print('Successful auth from MAC %s' % str(client_mac))

    def failure_handler(self, client_mac, port_id_mac):  # pylint: disable=unused-argument
        self.failure_counter += 1
        print('failure from MAC %s' % str(client_mac))

    def receive_eth_packet(self):
        """Receive Ethernet Frame and send to State Machine"""
        rad_queue_size = self.radius_output_queue.qsize()
        message = EthernetPacket(self.PORT_ID_MAC, str(self.src_mac), 0x888e, "")
        self.sm.event(EventMessageReceived(message, self.PORT_ID_MAC))
        self.assertEqual(self.radius_output_queue.qsize(), rad_queue_size + 1)

    def receive_radius_accept(self):
        """Receive Radius AccessAccept Packet and send to State Machine"""
        rad_queue_size = self.radius_output_queue.qsize()
        message = RadiusAccessAccept(1, 1, [])
        self.sm.event(EventRadiusMessageReceived(message, None, []))
        self.assertEqual(self.radius_output_queue.qsize(), rad_queue_size)

    def receive_radius_reject(self):
        """Receive Radius AccessReject Packet and send to State Machine"""
        rad_queue_size = self.radius_output_queue.qsize()
        message = RadiusAccessReject(1, 1, [])
        self.sm.event(EventRadiusMessageReceived(message, None, []))
        self.assertEqual(self.radius_output_queue.qsize(), rad_queue_size)

    def test_smoke_test_send_request(self):
        """Smoke Test Send RADIUS MAB Request on Receiving DHCP Activity"""
        self.sm.port_enabled = True

        self.receive_eth_packet()
        radius_output = self.radius_output_queue.get_nowait()
        self.assertEqual(self.sm.AAA_IDLE, self.sm.state)
        self.assertEqual(radius_output[0], str(self.src_mac))

    @check_counters(expected_auth_counter=1)
    def test_smoke_test_success_radius(self):
        """Smoke Test successful RADIUS Request"""
        self.sm.port_enabled = True
        self.receive_eth_packet()

        radius_output = self.radius_output_queue.get_nowait()
        self.assertEqual(self.sm.AAA_IDLE, self.sm.state)
        self.assertEqual(radius_output[0], str(self.src_mac))

        self.receive_radius_accept()
        self.assertEqual(self.sm.AAA_SUCCESS, self.sm.state)

    @check_counters(expected_failure_counter=1)
    def test_smoke_test_fail_radius(self):
        """Smoke Test incorrect details sent to RADIUS Server"""
        self.sm.port_enabled = True
        self.receive_eth_packet()

        radius_output = self.radius_output_queue.get_nowait()
        self.assertEqual(self.sm.AAA_IDLE, self.sm.state)
        self.assertEqual(radius_output[0], str(self.src_mac))

        self.receive_radius_reject()
        self.assertEqual(self.sm.AAA_FAILURE, self.sm.state)

    @check_counters(expected_failure_counter=1, expected_auth_counter=1)
    def test_fail_first_attempt_then_success(self):
        """Smoke Test incorrect details sent to RADIUS Server"""
        self.sm.port_enabled = True
        self.test_smoke_test_fail_radius()
        self.test_smoke_test_success_radius()
