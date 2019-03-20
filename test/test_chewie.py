"""Unittests for chewie/chewie.py"""

import logging
import random
import sys
import tempfile
import unittest
from unittest.mock import patch

import eventlet
from eventlet.queue import Queue

from chewie.chewie import Chewie
from chewie.eap_state_machine import FullEAPStateMachine
from chewie.mac_address import MacAddress
from helpers import FakeTimerScheduler


FROM_SUPPLICANT = Queue()
TO_SUPPLICANT = Queue()
FROM_RADIUS = Queue()
TO_RADIUS = Queue()


def patch_things(func):
    """decorator to mock patch socket operations and random number generators"""
    @patch('chewie.chewie.get_random_id', get_random_id_helper)
    @patch('chewie.chewie.EapSocket', FakeEapSocket)
    @patch('chewie.chewie.RadiusSocket', FakeRadiusSocket)
    @patch('chewie.chewie.RadiusLifecycle.generate_request_authenticator', urandom_helper)
    @patch('chewie.chewie.FullEAPStateMachine.next_id', next_id)
    def wrapper_patch(self):
        func(self)

    return wrapper_patch


def setup_generators(_supplicant_replies=None, _radius_replies=None):
    """decorator to setup the packets for the mocked socket (queues) to send"""
    def decorator_setup_gen(func):
        def wrapper_setup_gen(self):
            global SUPPLICANT_REPLY_GENERATOR  # pylint: disable=global-statement
            global RADIUS_REPLY_GENERATOR  # pylint: disable=global-statement
            global URANDOM_GENERATOR  # pylint: disable=global-statement
            global GET_RANDOM_ID_GENERATOR

            SUPPLICANT_REPLY_GENERATOR = supplicant_replies_gen(_supplicant_replies)
            RADIUS_REPLY_GENERATOR = radius_replies_gen(_radius_replies)
            URANDOM_GENERATOR = urandom()
            GET_RANDOM_ID_GENERATOR = fake_get_random_id()
            func(self)
        return wrapper_setup_gen
    return decorator_setup_gen


def fake_get_random_id():
    for i in [103, 0x99]:
        yield i


GET_RANDOM_ID_GENERATOR = None


def get_random_id_helper():  # pylint: disable=unused-argument
    """helper for urandom_generator"""
    return next(GET_RANDOM_ID_GENERATOR)


def supplicant_replies_gen(replies):
    """generator for packets supplicant sends"""
    for reply in replies:
        yield reply


def radius_replies_gen(replies):
    """generator for packets radius sends"""
    for reply in replies:
        yield reply


def urandom():
    """generator for urandom"""
    _list = [b'\x87\xf5[\xa71\xeeOA;}\\t\xde\xd7.=',
             b'\xf7\xe0\xaf\xc7Q!\xa2\xa9\xa3\x8d\xf7\xc6\x85\xa8k\x06']
    for random_bytes in _list:
        yield random_bytes


URANDOM_GENERATOR = None  # urandom()


def urandom_helper(size):  # pylint: disable=unused-argument
    """helper for urandom_generator"""
    return next(URANDOM_GENERATOR)


SUPPLICANT_REPLY_GENERATOR = None  # supplicant_replies()
RADIUS_REPLY_GENERATOR = None  # radius_replies()


class FakeEapSocket:
    def __init__(self, _interface_name):
        # TODO inject queues in constructor instead of using globals
        pass

    def setup(self):
        pass

    def receive(self):  # pylint: disable=unused-argument
        global FROM_SUPPLICANT

        print('mocked eap_receive')
        got = FROM_SUPPLICANT.get()
        return got

    def send(self, data=None):  # pylint: disable=unused-argument
        global TO_SUPPLICANT
        global FROM_SUPPLICANT
        global SUPPLICANT_REPLY_GENERATOR

        print('mocked eap_send')
        if data:
            TO_SUPPLICANT.put_nowait(data)
        try:
            next_reply = next(SUPPLICANT_REPLY_GENERATOR)
        except StopIteration:
            return
        if next_reply:
            FROM_SUPPLICANT.put_nowait(next_reply)


class FakeRadiusSocket:
    def __init__(self, _listen_ip, _listen_port, _server_ip, _server_port):
        # TODO inject queues in constructor instead of using globals
        pass

    def setup(self):
        pass

    def receive(self):  # pylint: disable=unused-argument
        global FROM_RADIUS

        print('mocked radius_receive')
        got = FROM_RADIUS.get()
        print('got RADIUS', got)
        return got

    def send(self, data):  # pylint: disable=unused-argument
        global TO_RADIUS
        global FROM_RADIUS
        global RADIUS_REPLY_GENERATOR

        print('mocked radius_send')
        TO_RADIUS.put_nowait(data)
        try:
            next_reply = next(RADIUS_REPLY_GENERATOR)
        except StopIteration:
            return
        if next_reply:
            FROM_RADIUS.put_nowait(next_reply)


def do_nothing(chewie):  # pylint: disable=unused-argument
    """Mock function that does nothing.
     Typically used on socket opening/configuration operations"""
    pass


def next_id(eap_state_machine):  # pylint: disable=invalid-name
    """mocked FullEAPStateMachine.nextId"""
    if eap_state_machine.current_id is None:
        return 116
    _id = eap_state_machine.current_id + 1
    if _id > 255:
        return random.randint(0, 200)
    return _id


def auth_handler(client_mac, port_id_mac):  # pylint: disable=unused-argument
    """dummy handler for successful authentications"""
    print('Successful auth from MAC %s on port: %s' % (str(client_mac), str(port_id_mac)))


def failure_handler(client_mac, port_id_mac):  # pylint: disable=unused-argument
    """dummy handler for failed authentications"""
    print('failure from MAC %s on port: %s' % (str(client_mac), str(port_id_mac)))


def logoff_handler(client_mac, port_id_mac):  # pylint: disable=unused-argument
    """dummy handler for logoffs"""
    print('logoff from MAC %s on port: %s' % (str(client_mac), str(port_id_mac)))


class ChewieTestCase(unittest.TestCase):
    """Main chewie.py test class"""

    no_radius_replies = []

    header = "0000000000010242ac17006f888e"
    sup_replies_success = [bytes.fromhex(header + "01000009027400090175736572"),
                           bytes.fromhex(
                               header + "010000160275001604103abcadc86714b2d75d09dd7ff53edf6b")]

    radius_replies_success = [bytes.fromhex(
        "0b000050066300262c8ee8a33f43ad4e837e63c54f180175001604101a16a3baa37a0238f33384f6c11067425012a3bf83bea0eeb69645088527dc491eed18126aa866456add628e3a55a4737872cad6"),
                              bytes.fromhex(
                                  "02010032ec22830bb2fbde37f635e91690410b334f060375000450129a08d246ec3da2f371ec4ff16eed9310010675736572")]

    sup_replies_logoff = [bytes.fromhex(header + "01000009027400090175736572"),
                          bytes.fromhex(
                              header + "010000160275001604103abcadc86714b2d75d09dd7ff53edf6b"),
                          bytes.fromhex("0000000000010242ac17006f888e01020000")]

    # packet id (0x84 is incorrect)
    sup_replies_failure_message_id = [bytes.fromhex(header + "01000009028400090175736572"),
                                      bytes.fromhex(header + "01000009029400090175736572"),
                                      bytes.fromhex(header + "01000009026400090175736572"),
                                      bytes.fromhex(header + "01000009025400090175736572")]

    # the first response has correct code, second is wrong and will be dropped by radius
    sup_replies_failure2_response_code = [bytes.fromhex(header + "01000009027400090175736572"),
                                          bytes.fromhex(header + "01000009037400090175736572")]

    def setUp(self):
        logger = logging.getLogger()
        logger.level = logging.DEBUG
        self.log_file = tempfile.NamedTemporaryFile()

        logger.addHandler(logging.FileHandler(self.log_file.name))
        logger.addHandler(logging.StreamHandler(sys.stdout))

        self.chewie = Chewie('lo', logger,
                             auth_handler, failure_handler, logoff_handler,
                             '127.0.0.1', 1812, 'SECRET',
                             '44:44:44:44:44:44')
        self.fake_scheduler = FakeTimerScheduler()
        self.chewie.timer_scheduler = self.fake_scheduler

        global FROM_SUPPLICANT  # pylint: disable=global-statement
        global TO_SUPPLICANT  # pylint: disable=global-statement
        global FROM_RADIUS  # pylint: disable=global-statement
        global TO_RADIUS  # pylint: disable=global-statement

        FROM_SUPPLICANT = Queue()
        TO_SUPPLICANT = Queue()
        FROM_RADIUS = Queue()
        TO_RADIUS = Queue()

    def tearDown(self):
        self.chewie.shutdown()

    def test_get_state_machine(self):
        """Tests Chewie.get_state_machine()"""
        self.assertEqual(len(self.chewie.state_machines), 0)
        # creates the state_machine if it doesn't exist
        state_machine = self.chewie.get_state_machine('12:34:56:78:9a:bc',  # pylint: disable=invalid-name
                                                      '00:00:00:00:00:01')

        self.assertEqual(len(self.chewie.state_machines), 1)

        self.assertIs(state_machine, self.chewie.get_state_machine('12:34:56:78:9a:bc',
                                                                   '00:00:00:00:00:01'))

        self.assertIsNot(state_machine, self.chewie.get_state_machine('12:34:56:78:9a:bc',
                                                                      '00:00:00:00:00:02'))
        self.assertIsNot(state_machine, self.chewie.get_state_machine('ab:cd:ef:12:34:56',
                                                                      '00:00:00:00:00:01'))

        # 2 ports
        self.assertEqual(len(self.chewie.state_machines), 2)
        # port 1 has 2 macs
        self.assertEqual(len(self.chewie.state_machines['00:00:00:00:00:01']), 2)
        # port 2 has 1 mac
        self.assertEqual(len(self.chewie.state_machines['00:00:00:00:00:02']), 1)

    def test_get_state_machine_by_packet_id(self):
        """Tests Chewie.get_state_machine_by_packet_id()"""
        self.chewie.radius_lifecycle.packet_id_to_mac[56] = {'src_mac': '12:34:56:78:9a:bc',
                                                             'port_id': '00:00:00:00:00:01'}
        state_machine = self.chewie.get_state_machine('12:34:56:78:9a:bc',  # pylint: disable=invalid-name
                                                      '00:00:00:00:00:01')

        self.assertIs(self.chewie.get_state_machine_from_radius_packet_id(56),
                      state_machine)
        with self.assertRaises(KeyError):
            self.chewie.get_state_machine_from_radius_packet_id(20)

    @patch_things
    @setup_generators(sup_replies_success, radius_replies_success)
    def test_success_dot1x(self):
        """Test success api"""
        FROM_SUPPLICANT.put_nowait(bytes.fromhex("0000000000010242ac17006f888e01010000"))

        pool = eventlet.GreenPool()
        pool.spawn(self.chewie.run)

        eventlet.sleep(1)

        self.assertEqual(
            self.chewie.get_state_machine('02:42:ac:17:00:6f',
                                          '00:00:00:00:00:01').state,
            FullEAPStateMachine.SUCCESS2)

    @patch_things
    def test_port_status_changes(self):
        """test port status api and that identity request is sent after port up"""

        global TO_SUPPLICANT
        pool = eventlet.GreenPool()
        pool.spawn(self.chewie.run)
        eventlet.sleep(1)
        self.chewie.port_down("00:00:00:00:00:01")

        self.chewie.port_up("00:00:00:00:00:01")

        while not self.fake_scheduler.jobs:
            eventlet.sleep(0.1)
        self.fake_scheduler.run_jobs(num_jobs=1)
        # check preemptive sent directly after port up
        out_packet = TO_SUPPLICANT.get()
        self.assertEqual(out_packet,
                         bytes.fromhex('0180C2000003000000000001888e010000050167000501'))

        # check there is a new job in the queue for sending the next id request.
        # This will keep adding jobs forever.
        self.assertEqual(len(self.fake_scheduler.jobs), 1)
        self.assertEqual(self.fake_scheduler.jobs[0].function.__name__,
                         Chewie.send_preemptive_identity_request_if_no_active_on_port.__name__)

    @patch_things
    @setup_generators(sup_replies_logoff, radius_replies_success)
    def test_logoff_dot1x(self):
        """Test logoff"""
        self.chewie.get_state_machine(MacAddress.from_string('02:42:ac:17:00:6f'),
                                      MacAddress.from_string('00:00:00:00:00:01'))
        FROM_SUPPLICANT.put_nowait(bytes.fromhex("0000000000010242ac17006f888e01010000"))

        pool = eventlet.GreenPool()
        pool.spawn(self.chewie.run)

        eventlet.sleep(0.1)

        self.assertEqual(
            self.chewie.get_state_machine('02:42:ac:17:00:6f',
                                          '00:00:00:00:00:01').state,
            FullEAPStateMachine.LOGOFF2)

    @patch_things
    @setup_generators(sup_replies_failure_message_id, no_radius_replies)
    def test_failure_message_id_dot1x(self):
        """Test incorrect message id results in timeout_failure"""
        # TODO not convinced this is transitioning through the correct states.
        # (should be discarding all packets)
        # But end result is correct (both packets sent/received, and end state)self.chewie.get_state_machine(MacAddress.from_string('02:42:ac:17:00:6f'),
        self.chewie.get_state_machine(MacAddress.from_string('02:42:ac:17:00:6f'),
                                      MacAddress.from_string(
                                          '00:00:00:00:00:01')).DEFAULT_TIMEOUT = 0.5

        FROM_SUPPLICANT.put_nowait(bytes.fromhex("0000000000010242ac17006f888e01010000"))

        pool = eventlet.GreenPool()
        pool.spawn(self.chewie.run)

        while not self.fake_scheduler.jobs:
            eventlet.sleep(0.1)
        self.fake_scheduler.run_jobs()

        self.assertEqual(
            self.chewie.get_state_machine('02:42:ac:17:00:6f',
                                          '00:00:00:00:00:01').state,
            FullEAPStateMachine.TIMEOUT_FAILURE)


    @patch_things
    @setup_generators(sup_replies_failure2_response_code, no_radius_replies)
    def test_failure2_resp_code_dot1x(self):
        """Test incorrect eap.code results in timeout_failure2. RADIUS Server drops it.
        It is up to the supplicant to send another request - this supplicant doesnt"""
        self.chewie.get_state_machine(MacAddress.from_string('02:42:ac:17:00:6f'),
                                      MacAddress.from_string(
                                          '00:00:00:00:00:01')).DEFAULT_TIMEOUT = 0.5

        FROM_SUPPLICANT.put_nowait(bytes.fromhex("0000000000010242ac17006f888e01010000"))

        pool = eventlet.GreenPool()
        pool.spawn(self.chewie.run)

        while not self.fake_scheduler.jobs:
            eventlet.sleep(0.1)
        self.fake_scheduler.run_jobs()

        self.assertEqual(
            self.chewie.get_state_machine('02:42:ac:17:00:6f',
                                          '00:00:00:00:00:01').state,
            FullEAPStateMachine.TIMEOUT_FAILURE2)
