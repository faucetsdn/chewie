"""Unittests for chewie/chewie.py"""

import logging
import sys
import tempfile
import time
import unittest
from queue import Queue
from threading import Thread
from unittest.mock import patch, MagicMock

from eventlet.greenpool import GreenPool
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
    print('mocked eap_receive')
    got =  FROM_SUPPLICANT.get()
    print('got EAP', got)
    return got


def eap_send(chewie, data):
    print('mocked eap_send')
    TO_SUPPLICANT.put(data)
    try:
        n = next(SUPPLICANT_REPLY_GENERATOR)
    except StopIteration:
        return
    if n:
        FROM_SUPPLICANT.put(n)


def radius_receive(chewie):
    print('mocked radius_receive')
    got =  FROM_RADIUS.get()
    print('got RADIUS', got)
    return got


def radius_send(chewie, data):
    print('mocked radius_send')
    TO_RADIUS.put(data)
    try:
        n = next(RADIUS_REPLY_GENERATOR)
    except StopIteration:
        return
    if n:
        FROM_RADIUS.put(n)


def open_socket(chewie):
    print('mocked open_socket')
    pass


def run(chewie):
    print('Starting mocked')
    chewie.logger.info("Starting mocked")
    chewie.open_radius_socket()
    chewie.logger.info('opened radius socket')
    chewie.start_threads_and_wait()
    chewie.logger.info("chewie finished")


def auth_handler(chewie, client_mac, port_id_mac):  # pylint: disable=unused-argument
    """dummy handler for successful authentications"""
    print('Successful auth from MAC %s on port: %s' % (str(client_mac), str(port_id_mac)))


def failure_handler(chewie, client_mac, port_id_mac):  # pylint: disable=unused-argument
    """dummy handler for failed authentications"""
    print('failure from MAC %s on port: %s' % (str(client_mac), str(port_id_mac)))


def logoff_handler(chewie, client_mac, port_id_mac):  # pylint: disable=unused-argument
    """dummy handler for logoffs"""
    print('logoff from MAC %s on port: %s' % (str(client_mac), str(port_id_mac)))


class ChewieTestCase(unittest.TestCase):
    """Main chewie.py test class"""

    # @patch('chewie.chewie.Chewie.radius_send', radius_send)
    # @patch('chewie.chewie.Chewie.radius_receive', radius_receive)
    # @patch('chewie.chewie.Chewie.eap_send', eap_send)
    # @patch('chewie.chewie.Chewie.eap_receive', eap_receive)
    # @patch('chewie.chewie.Chewie.run', run)
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

    def test_get_sm(self):
        """Tests Chewie.get_state_machine()"""
        self.assertEqual(len(self.chewie.state_machines), 0)
        # creates the sm if it doesn't exist
        sm = self.chewie.get_state_machine('12:34:56:78:9a:bc',  # pylint: disable=invalid-name
                                           '00:00:00:00:00:01')

        self.assertEqual(len(self.chewie.state_machines), 1)

        self.assertIs(sm, self.chewie.get_state_machine('12:34:56:78:9a:bc',
                                                        '00:00:00:00:00:01'))

        self.assertIsNot(sm, self.chewie.get_state_machine('12:34:56:78:9a:bc',
                                                           '00:00:00:00:00:02'))
        self.assertIsNot(sm, self.chewie.get_state_machine('ab:cd:ef:12:34:56',
                                                           '00:00:00:00:00:01'))

        # 2 ports
        self.assertEqual(len(self.chewie.state_machines), 2)
        # port 1 has 2 macs
        self.assertEqual(len(self.chewie.state_machines['00:00:00:00:00:01']), 2)
        # port 2 has 1 mac
        self.assertEqual(len(self.chewie.state_machines['00:00:00:00:00:02']), 1)

    def test_get_sm_by_packet_id(self):
        """Tests Chewie.get_sm_by_packet_id()"""
        self.chewie.packet_id_to_mac[56] = {'src_mac': '12:34:56:78:9a:bc',
                                            'port_id': '00:00:00:00:00:01'}
        sm = self.chewie.get_state_machine('12:34:56:78:9a:bc',  # pylint: disable=invalid-name
                                           '00:00:00:00:00:01')

        self.assertIs(self.chewie.get_state_machine_from_radius_packet_id(56),
                      sm)
        with self.assertRaises(KeyError):
            self.chewie.get_state_machine_from_radius_packet_id(20)

    def test_get_next_radius_packet_id(self):
        """Tests Chewie.get_next_radius_packet_id()"""
        for i in range(0, 260):
            _i = i % 256
            self.assertEqual(self.chewie.get_next_radius_packet_id(),
                             _i)

    # @unittest.skip('mocking doesnt work yet')
    def test_success_dot1x(self):
        """Test success api"""
        with patch('chewie.chewie.Chewie.radius_receive', radius_receive):
            with patch('chewie.chewie.Chewie.radius_send', radius_send):
                with patch('chewie.chewie.Chewie.eap_send', eap_send):
                    with patch('chewie.chewie.Chewie.eap_receive', eap_receive):
                        with patch('chewie.chewie.Chewie.run', run):
                            thread = Thread(target=self.chewie.run)

                            thread.start()
                            # self.pool = GreenPool()
                            # self.eventlets = []
                            #
                            # self.eventlets.append(self.pool.spawn(self.chewie.run))

                            time.sleep(15)
                            FROM_SUPPLICANT.put(build_byte_string("0000000000010242ac17006f888e01010000"))
                            time.sleep(10)

                            print(self.chewie.eap_output_messages.queue)
                            print(self.chewie.radius_output_messages.queue)

                            with open(self.log_file.name) as log:
                                print(log.read())

                            self.assertEquals(
                                self.chewie.get_state_machine('02:42:ac:17:00:6f',
                                                              '00:00:00:00:00:01').currentState,
                                FullEAPStateMachine.SUCCESS2)
