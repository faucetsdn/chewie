import os
import struct

from hashlib import md5
from eventlet.queue import Queue
from .event import EventMessageReceived
from .message_parser import IdentityMessage, Md5ChallengeMessage, EapolStartMessage
from .message_parser import SuccessMessage, FailureMessage
from .eap import Eap

def generate_txn_id():
    return ord(os.urandom(1))

def generate_random_bytes(num_bytes):
    return os.urandom(num_bytes)

class StateMachine:
    def __init__(self, src_mac):
        self.src_mac = src_mac

        self.txn_id = None
        self.challenge = None
        self.expected_response = None
        # TODO - some way to query for this based on identity
        self.password = "microphone"
        self.state = "idle"
        self.output_messages = Queue()

        self.txn_id_method = generate_txn_id
        self.challenge_method = generate_random_bytes

    def event(self, event):
        if isinstance(event, EventMessageReceived):
            self.handle_message_received(event.message)

    def handle_message_received(self, message):
        if self.state == "idle":
            self.handle_idle_message(message)
        elif self.state == "identity request sent":
            self.handle_identity_sent_message(message)
        elif self.state == "challenge sent":
            self.handle_challenge_sent_message(message)

    def handle_idle_message(self, message):
        if isinstance(message, EapolStartMessage):
            self.txn_id = self.txn_id_method()
            identity_request = IdentityMessage(self.src_mac, self.txn_id, Eap.REQUEST, "")
            self.output_messages.put(identity_request)
            self.state = "identity request sent"

    def handle_identity_sent_message(self, message):
        if isinstance(message, IdentityMessage):
            self.challenge = self.challenge_method(16)
            self.calculate_expected_response()
            challenge_request = Md5ChallengeMessage(self.src_mac, self.txn_id, Eap.REQUEST, self.challenge, b"")
            self.output_messages.put(challenge_request)
            self.state = "challenge sent"

    def handle_challenge_sent_message(self, message):
        if isinstance(message, Md5ChallengeMessage):
            if message.challenge == self.expected_response:
                message = SuccessMessage(self.src_mac, self.txn_id)
                self.output_messages.put(message)
                self.state = "authenticated"
            else:
                message = FailureMessage(self.src_mac, self.txn_id)
                self.output_messages.put(message)
                self.state = "idle"

    def calculate_expected_response(self):
        txn_id_string = struct.pack("B", self.txn_id)
        self.expected_response = md5(txn_id_string + self.password.encode() + self.challenge).digest()
