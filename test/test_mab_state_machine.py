import logging
from queue import Queue
import tempfile
import unittest
from chewie.event import EventMessageReceived, EventRadiusMessageReceived
from chewie.mac_address import MacAddress
from chewie.ethernet_packet import EthernetPacket
from chewie.state_machines.mab_state_machine import MacAuthenticationBypassStateMachine
from chewie.radius import RadiusAccessReject, RadiusAccessAccept


# TODO Remove and create a 'test state machine' class
def check_counters(_func=None, *,
                   expected_auth_counter=0, expected_failure_counter=0, expected_logoff_counter=0):
    """Decorator to check the handlers have been called the
     correct number of times at the end of each test"""
    def decorator_check_counters(func):
        def wrapper(self):

            start_auth_counter = self.auth_counter
            start_failure_counter = self.failure_counter
            start_logoff_counter = self.logoff_counter
            ret = func(self)
            self.assertEqual(self.auth_counter,
                             start_auth_counter + expected_auth_counter)
            self.assertEqual(self.failure_counter,
                             start_failure_counter + expected_failure_counter)
            self.assertEqual(self.logoff_counter,
                             start_logoff_counter + expected_logoff_counter)
            return ret

        return wrapper
    if _func is None:
        return decorator_check_counters
    else:
        return decorator_check_counters(_func)

class MABStateMachineTest(unittest.TestCase):

    PORT_ID_MAC = MacAddress.from_string("00:00:00:00:00:01")

    def setUp(self):
        # Build the state machine
        logger = logging.getLogger()
        logger.level = logging.DEBUG
        self.log_file = tempfile.NamedTemporaryFile()
        logger.addHandler(logging.FileHandler(self.log_file.name))

        self.eap_output_queue = Queue()
        self.radius_output_queue = Queue()
        # TODO reset
        self.timer_scheduler = None
        self.src_mac = MacAddress.from_string("00:12:34:56:78:90")
        log_prefix = "chewie.SM - port: %s, client: %s" % (self.src_mac, self.PORT_ID_MAC)

        self.sm = MacAuthenticationBypassStateMachine(self.eap_output_queue, self.radius_output_queue,
                                                      self.src_mac,
                                                      self.timer_scheduler, self.auth_handler, self.failure_handler,
                                                      self.logoff_handler,
                                                      log_prefix)

        self.auth_counter = 0
        self.failure_counter = 0
        self.logoff_counter = 0


    def tearDown(self):
        with open(self.log_file.name) as log:
            self.assertNotIn('aaaEapResp is true. but data is false. This should never happen',
                             log.read())

    def auth_handler(self, client_mac, port_id_mac, timer, vlan_name, filter_id):  # pylint: disable=unused-argument
        self.auth_counter += 1
        print('Successful auth from MAC %s' % str(client_mac))

    def failure_handler(self, client_mac, port_id_mac):  # pylint: disable=unused-argument
        self.failure_counter += 1
        print('failure from MAC %s' % str(client_mac))

    def logoff_handler(self, client_mac, port_id_mac):  # pylint: disable=unused-argument
        self.logoff_counter += 1
        print('logoff from MAC %s' % str(client_mac))

    def receive_eth_packet(self):
        rad_queue_size = self.radius_output_queue.qsize()
        eap_queue_size = self.eap_output_queue.qsize()

        message = EthernetPacket(self.PORT_ID_MAC, str(self.src_mac), 0x888e, "")
        self.sm.event(EventMessageReceived(message, self.PORT_ID_MAC))

        self.assertEqual(self.radius_output_queue.qsize(), rad_queue_size + 1)
        self.assertEqual(self.eap_output_queue.qsize(), eap_queue_size)

    def receive_radius_accept(self):
        rad_queue_size = self.radius_output_queue.qsize()
        eap_queue_size = self.eap_output_queue.qsize()

        message = RadiusAccessAccept(1, 1, [])
        self.sm.event(EventRadiusMessageReceived(message, None, []))

        self.assertEqual(self.radius_output_queue.qsize(), rad_queue_size)
        self.assertEqual(self.eap_output_queue.qsize(), eap_queue_size)

    def receive_radius_reject(self):
        rad_queue_size = self.radius_output_queue.qsize()
        eap_queue_size = self.eap_output_queue.qsize()

        message = RadiusAccessReject(1, 1, [])
        self.sm.event(EventRadiusMessageReceived(message, None, []))

        self.assertEqual(self.radius_output_queue.qsize(), rad_queue_size)
        self.assertEqual(self.eap_output_queue.qsize(), eap_queue_size)

    def test_smoke_test_send_request(self):
        self.sm.port_enabled = True

        self.receive_eth_packet()
        radius_output = self.radius_output_queue.get_nowait()
        self.assertEqual(self.sm.AAA_IDLE, self.sm.state)
        self.assertEqual(radius_output[0], str(self.src_mac))

    def test_smoke_test_success_radius(self):
        self.sm.port_enabled = True
        self.receive_eth_packet()

        radius_output = self.radius_output_queue.get_nowait()
        self.assertEqual(self.sm.AAA_IDLE, self.sm.state)
        self.assertEqual(radius_output[0], str(self.src_mac))
        # Receive Radius Accept
        self.receive_radius_accept()
        self.assertEqual(self.sm.AAA_SUCCESS, self.sm.state)

    def test_smoke_test_fail_radius(self):
        self.sm.port_enabled = True
        self.receive_eth_packet()

        radius_output = self.radius_output_queue.get_nowait()
        self.assertEqual(self.sm.AAA_IDLE, self.sm.state)
        self.assertEqual(radius_output[0], str(self.src_mac))
        # Receive Radius Accept
        self.receive_radius_reject()

        self.assertEqual(self.sm.AAA_FAILURE, self.sm.state)
