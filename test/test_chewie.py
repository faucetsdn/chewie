import logging
import time
import unittest
from queue import Queue
from threading import Thread
from unittest.mock import patch, MagicMock

from netils import build_byte_string

from chewie.chewie import Chewie
from chewie.eap_state_machine import FullEAPStateMachine

FROM_SUPPLICANT = Queue()
TO_SUPPLICANT = Queue()
FROM_RADIUS = Queue()
TO_RADIUS = Queue()


def supplicant_replies():
    header = "0000000000010242ac17006f888e"
    replies = [build_byte_string(header + "01000009027400090175736572"),
               build_byte_string(header + "010000160275001604103abcadc86714b2d75d09dd7ff53edf6b")]
    for r in replies:
        yield r


def radius_replies():
    replies = [build_byte_string("0b040050e5e40d846576a2310755e906c4b2b5064f180175001604101a16a3baa37a0238f33384f6c11067425012ce61ba97026b7a05b194a930a922405218126aa866456add628e3a55a4737872cad6"),
               build_byte_string("02050032fb4c4926caa21a02f74501a65c96f9c74f06037500045012c060ca6a19c47d0998c7b20fd4d771c1010675736572")]
    for r in replies:
        yield r


def urandom():
    _list = [b'\x87\xf5[\xa71\xeeOA;}\\t\xde\xd7.=',
             b'\xf7\xe0\xaf\xc7Q!\xa2\xa9\xa3\x8d\xf7\xc6\x85\xa8k\x06']
    for l in _list:
        yield l


URANDOM_GENERATOR = urandom()


def urandom_helper(size):
    return next(URANDOM_GENERATOR)


SUPPLICANT_REPLY_GENERATOR = supplicant_replies()
RADIUS_REPLY_GENERATOR = radius_replies()



def eap_receive(chewie):
    return FROM_SUPPLICANT.get()


def eap_send(chewie, data):
    TO_SUPPLICANT.put(data)
    try:
        n = next(SUPPLICANT_REPLY_GENERATOR)
    except StopIteration:
        return
    if n:
        FROM_SUPPLICANT.put(n)


def radius_receive(chewie):
    return FROM_RADIUS.get()


def radius_send(chewie, data):
    TO_RADIUS.put(data)
    try:
        n = next(RADIUS_REPLY_GENERATOR)
    except StopIteration:
        return
    if n:
        FROM_RADIUS.put(n)


def open_socket(chewie):
    pass


def run(chewie):
    chewie.logger.info("Starting")
    chewie.open_radius_socket()
    chewie.start_threads_and_wait()


class ChewieTestCase(unittest.TestCase):

    @patch('chewie.chewie.Chewie.radius_send', radius_send)
    @patch('chewie.chewie.Chewie.radius_receive', radius_receive)
    @patch('chewie.chewie.Chewie.eap_send', eap_send)
    @patch('chewie.chewie.Chewie.eap_receive', eap_receive)
    @patch('chewie.chewie.Chewie.run', run)
    def setUp(self):
        logger = logging.getLogger()

        self.chewie = Chewie('lo', logger,
                             self.auth_handler, self.failure_handler, self.logoff_handler,
                             '127.0.0.1', 1812, 'SECRET',
                             '44:44:44:44:44:44')
        # self.thread = Thread(target=self.chewie.run)

    def auth_handler(self, client_mac, port_id_mac):
        print('Successful auth from MAC %s' % str(client_mac))

    def failure_handler(self, client_mac, port_id_mac):
        print('failure from MAC %s' % str(client_mac))

    def logoff_handler(self, client_mac, port_id_mac):
        print('logoff from MAC %s' % str(client_mac))

    def test_get_sm(self):
        self.assertEqual(len(self.chewie.state_machines), 0)
        # creates the sm if it doesn't exist
        sm = self.chewie.get_state_machine('12:34:56:78:9a:bc')

        self.assertEqual(len(self.chewie.state_machines), 1)

        self.assertIs(sm, self.chewie.get_state_machine('12:34:56:78:9a:bc'))

        self.assertEqual(len(self.chewie.state_machines), 1)

    def test_get_sm_by_packet_id(self):
        self.chewie.packet_id_to_mac[56] = '12:34:56:78:9a:bc'
        sm = self.chewie.get_state_machine('12:34:56:78:9a:bc')

        self.assertIs(self.chewie.get_state_machine_from_radius_packet_id(56),
                      sm)
        with self.assertRaises(KeyError):
            self.chewie.get_state_machine_from_radius_packet_id(20)

    def test_get_next_radius_packet_id(self):

        for i in range(0, 260):
            _i = i % 256
            self.assertEqual(self.chewie.get_next_radius_packet_id(),
                             _i)

    @unittest.skip('mocking doesnt work yet')
    def test_success_dot1x(self):
        """Test success api"""
        self.thread.start()
        FROM_SUPPLICANT.put(build_byte_string("0000000000010242ac17006f888e01010000"))
        time.sleep(5)

        self.assertEquals(self.chewie.get_state_machine('00:00:00:00:00:01').currentState,
                          FullEAPStateMachine.SUCCESS2)

