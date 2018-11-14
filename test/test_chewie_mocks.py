"""Unittests for chewie/chewie.py"""

from collections import namedtuple

import unittest
from unittest.mock import patch, Mock

from eventlet.queue import Queue

from chewie.chewie import Chewie

class FakeSocket:
    """Helper for socket wrappers"""

    def __init__(self):
        self.receive_queue = Queue()
        self.send_queue = Queue()

    def receive(self):
        """Fake receive method"""
        return self.receive_queue.get()

    def send(self, data):
        """Fake receive method"""
        self.send_queue.put(data)

FakeLogger = namedtuple('FakeLogger', ('name',)) # pylint: disable=invalid-name
FakeMessage = namedtuple('FakeMessage', ('src_mac',)) # pylint: disable=invalid-name

class ChewieWithMocksTestCase(unittest.TestCase):
    """Main chewie.py test class"""

    def setUp(self):
        self.chewie = Chewie('lo', FakeLogger('logger name'),
                             None, None, None,
                             '127.0.0.1', 1812, 'SECRET',
                             '44:44:44:44:44:44')

    @patch("chewie.chewie.Chewie.running", Mock(side_effect=[True, False]))
    @patch("chewie.chewie.MessageParser.ethernet_parse",
           Mock(return_value=[FakeMessage('fake src mac'), 'fake dst mac'])
          )
    @patch("chewie.chewie.sleep", Mock())
    def test_eap_packet_goes_to_new_state_machine(self):
        """test EAP packet creates a new state machine and is sent on"""
        self.chewie.eap_socket = FakeSocket()
        self.chewie.eap_socket.receive_queue.put("input eap message")
        self.chewie.receive_eap_messages()
        self.assertEqual(list(self.chewie.state_machines.keys()), ['fake dst mac'])
        self.assertEqual(list(self.chewie.state_machines['fake dst mac'].keys()), ['fake src mac'])
