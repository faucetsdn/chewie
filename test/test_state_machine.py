import unittest
import struct

from netils import build_byte_string
from hashlib import md5

from chewie.state_machine import StateMachine
from chewie.mac_address import MacAddress
from chewie.message_parser import IdentityMessage, Md5ChallengeMessage, EapolStartMessage
from chewie.event import EventMessageReceived
from chewie.eap import Eap

def txn_id_injector():
    return 123

def challenge_injector(_):
    return build_byte_string("01234567890abcdef01234567890abcdef")

def build_state_machine(src_mac):
    state_machine = StateMachine(src_mac)
    state_machine.txn_id_method = txn_id_injector
    state_machine.challenge_method = challenge_injector

    return state_machine

class StateMachineIdleTestCase(unittest.TestCase):
    def setUp(self):
        src_mac = MacAddress.from_string("00:aa:bb:cc:dd:ee")
        self.state_machine = build_state_machine(src_mac)
        self.assertEqual(self.state_machine.state, "idle")

    def test_packet_received_moves_to_authing_state(self):
        message = EapolStartMessage(MacAddress.from_string("00:12:34:56:78:90"))
        self.state_machine.event(EventMessageReceived(message))
        self.assertEqual(self.state_machine.state, "identity request sent")
        self.assertEqual(self.state_machine.output_messages.qsize(), 1)

class StateMachineIdentitySentTestCase(unittest.TestCase):
    def setUp(self):
        src_mac = MacAddress.from_string("00:aa:bb:cc:dd:ee")
        self.state_machine = build_state_machine(src_mac)
        self.assertEqual(self.state_machine.state, "idle")
        message = EapolStartMessage(MacAddress.from_string("00:12:34:56:78:90"))
        self.state_machine.event(EventMessageReceived(message))
        self.assertEqual(self.state_machine.state, "identity request sent")
        self.assertEqual(self.state_machine.output_messages.qsize(), 1)
        self.state_machine.output_messages.get()

    def test_identity_request_received_moves_to_challenge_sent(self):
        message = IdentityMessage(MacAddress.from_string("00:12:34:56:78:90"), 1, Eap.RESPONSE, "betelgeuse")
        self.state_machine.event(EventMessageReceived(message))
        self.assertEqual(self.state_machine.state, "challenge sent")
        self.assertEqual(self.state_machine.output_messages.qsize(), 1)

class StateMachineChallengeSentTestCase(unittest.TestCase):
    def setUp(self):
        src_mac = MacAddress.from_string("00:aa:bb:cc:dd:ee")
        self.state_machine = build_state_machine(src_mac)
        self.assertEqual(self.state_machine.state, "idle")
        message = EapolStartMessage(MacAddress.from_string("00:12:34:56:78:90"))
        self.state_machine.event(EventMessageReceived(message))
        self.assertEqual(self.state_machine.state, "identity request sent")
        self.assertEqual(self.state_machine.output_messages.qsize(), 1)
        self.state_machine.output_messages.get()
        message = IdentityMessage(MacAddress.from_string("00:12:34:56:78:90"), 1, Eap.RESPONSE, "betelgeuse")
        self.state_machine.event(EventMessageReceived(message))
        self.assertEqual(self.state_machine.state, "challenge sent")
        self.assertEqual(self.state_machine.output_messages.qsize(), 1)
        self.state_machine.output_messages.get()

    def test_correct_challenge_received_moves_to_authenticated(self):
        txn_id = 123
        challenge = build_byte_string("01234567890abcdef01234567890abcdef")
        password = "microphone"
        id_string = struct.pack("B", txn_id)
        challenge_response = md5(id_string + password.encode() + challenge).digest()
        message = Md5ChallengeMessage(
            MacAddress.from_string("00:12:34:56:78:90"), self.state_machine.txn_id, Eap.RESPONSE, challenge_response, b"who cares")
        self.state_machine.event(EventMessageReceived(message))
        self.assertEqual(self.state_machine.state, "authenticated")
        self.assertEqual(self.state_machine.output_messages.qsize(), 1)

    def test_incorrect_challenge_received_moves_to_idle(self):
        txn_id = 123
        challenge = build_byte_string("01234567890abcdef01234567890abcdef")
        password = "notmicrophone"
        id_string = struct.pack("B", txn_id)
        challenge_response = md5(id_string + password.encode() + challenge).digest()
        message = Md5ChallengeMessage(
            MacAddress.from_string("00:12:34:56:78:90"), self.state_machine.txn_id, Eap.RESPONSE, challenge_response, b"who cares")
        self.state_machine.event(EventMessageReceived(message))
        self.assertEqual(self.state_machine.state, "idle")
        self.assertEqual(self.state_machine.output_messages.qsize(), 1)
