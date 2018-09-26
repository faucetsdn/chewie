"""Unittests for chewie/chewie.py"""

import logging
import unittest

from chewie.chewie import Chewie


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

    def setUp(self):
        logger = logging.getLogger()

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
