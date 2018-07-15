
from queue import Queue
import unittest

from netils import build_byte_string

from chewie.eap import EapIdentity, Eap, EapMd5Challenge, EapSuccess
from chewie.mac_address import MacAddress
from chewie.message_parser import EapolStartMessage, IdentityMessage
from chewie.eap_state_machine import FullEAPStateMachine
from chewie.event import EventMessageReceived, EventRadiusMessageReceived


class FullStateMachineStartTestCase(unittest.TestCase):

    def setUp(self):
        self.eap_output_queue = Queue()
        self.radius_output_queue = Queue()
        self.src_mac = MacAddress.from_string("00:12:34:56:78:90")
        self.sm = FullEAPStateMachine(self.eap_output_queue, self.radius_output_queue, self.src_mac)
        self.sm.portEnabled = True
        self.sm.eapRestart = True

    def test_eap_start(self):
        # input EAPStart packet.
        # output EAPIdentityRequest on eap_output_q
        message = EapolStartMessage(self.src_mac)
        self.sm.event(EventMessageReceived(message))
        self.assertEqual(self.sm.currentState, self.sm.IDLE)

        self.assertEqual(self.eap_output_queue.qsize(), 1)
        output = self.eap_output_queue.queue[0][0]
        self.assertIsInstance(output, EapIdentity)
        self.assertEqual(self.radius_output_queue.qsize(), 0)

    def test_identity_response(self):
        self.test_eap_start()
        # input EapIdentityResponse
        # output EapIdentityResponse on radius_output_q
        message = IdentityMessage(self.src_mac, 1, Eap.RESPONSE, "host1user")
        self.sm.event(EventMessageReceived(message))
        self.assertEqual(self.sm.currentState, self.sm.AAA_IDLE)

        self.assertEqual(self.radius_output_queue.qsize(), 1)
        self.assertIsInstance(self.radius_output_queue.queue[0][0], IdentityMessage)
        self.assertEqual(self.eap_output_queue.qsize(), 1)

    def test_access_challenge(self):
        self.test_identity_response()

        eap_message = EapMd5Challenge(Eap.REQUEST, 2, build_byte_string("74d3db089b727d9cc5774599e4a32a29"), b"host1user")
        self.sm.event(EventRadiusMessageReceived(eap_message, None))
        self.assertEqual(self.sm.currentState, self.sm.IDLE2)

        self.assertEqual(self.eap_output_queue.qsize(), 2)
        self.assertIsInstance(self.eap_output_queue.queue[1][0], EapMd5Challenge)

        self.assertEqual(self.radius_output_queue.qsize(), 1)

    def test_md5_challenge_response(self):
        self.test_access_challenge()

        message = EapMd5Challenge(Eap.RESPONSE, 2, build_byte_string("3a535f0ee8c6b34fe714aa7dad9a0e15"), b"host1user")
        self.sm.event(EventMessageReceived(message))
        self.assertEqual(self.sm.currentState, self.sm.AAA_IDLE)
        self.assertEqual(self.eap_output_queue.qsize(), 2)
        self.assertEqual(self.radius_output_queue.qsize(), 2)
        self.assertIsInstance(self.radius_output_queue.queue[1][0], EapMd5Challenge)

    def test_access_accept(self):
        self.test_md5_challenge_response()

        message = EapSuccess(3)
        self.sm.event(EventRadiusMessageReceived(message, None))

        self.assertEqual(self.sm.currentState, self.sm.SUCCESS2)
        self.assertEqual(self.eap_output_queue.qsize(), 3)
        self.assertIsInstance(self.eap_output_queue.queue[2][0], EapSuccess)
        self.assertEqual(self.radius_output_queue.qsize(), 2)

    def MD5ChallengeEapTest(self):
        pass
        # input MD5Challenge (would've been from radius, but state machine does not know that)
        # output Md5Challenge on eap_output_q

    def EapSuccessTest(self):
        pass
        # input EAPSuccess (from radius)
        # output EAPSuccess on eap_output_q
        # will we need to fake the steps before getting to the success?

# pretend (via mocks) packets get received.
# check (again via mocks) the correct packet is outputed.
# could also check the state variables.