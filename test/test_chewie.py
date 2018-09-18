import logging
import unittest

from chewie.chewie import Chewie


class ChewieTestCase(unittest.TestCase):

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
