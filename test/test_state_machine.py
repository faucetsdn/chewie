import unittest

from chewie.state_machine import StateMachine
from chewie.mac_address import MacAddress
from chewie.message_parser import IdentityMessage, Md5ChallengeMessage

class EventPacketReceived(object):
    def __init__(self, src_mac):
        self.src_mac = src_mac
        self.type = "packet received"

class StateMachineIdleTestCase(unittest.TestCase):
    def test_packet_received_moves_to_authing_state(self):
        self.state_machine = StateMachine()
        self.assertEqual("idle", self.state_machine.state)
        self.state_machine.event(EventPacketReceived(MacAddress.from_string("00:12:34:56:78:90")))
        self.assertEqual("identity request sent", self.state_machine.state)
        self.assertEqual(self.state_machine.output_messages.qsize(), 1)

class StateMachineIdleTestCase(unittest.TestCase):
    def setUp(self):
        self.state_machine = StateMachine()
        self.assertEqual("idle", self.state_machine.state)
        self.state_machine.event(EventPacketReceived(MacAddress.from_string("00:12:34:56:78:90")))
        self.assertEqual("identity request sent", self.state_machine.state)
        self.assertEqual(self.state_machine.output_messages.qsize(), 1)

    def test_identity_request_received_moves_to_challenge_sent(self):
        self.state_machine.event(EventPacketReceived(MacAddress.from_string("00:12:34:56:78:90")))
