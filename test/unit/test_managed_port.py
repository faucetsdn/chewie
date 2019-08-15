import unittest
import logging
import tempfile
import sys

from eventlet.queue import Queue

from chewie.mac_address import MacAddress
from chewie.managed_port import ManagedPort
from helpers import FakeTimerScheduler


# pylint: disable=missing-docstring,
class ManagedPortTestCase(unittest.TestCase):

    def setUp(self):
        self.logger = logging.getLogger()
        self.logger.level = logging.DEBUG
        self.log_file = tempfile.NamedTemporaryFile()

        self.logger.addHandler(logging.FileHandler(self.log_file.name))
        self.logger.addHandler(logging.StreamHandler(sys.stdout))

        self.fake_scheduler = FakeTimerScheduler()
        self.timer_scheduler = self.fake_scheduler
        self.managed_port = None
        self.eap_output_messages = Queue()  # pylint: disable=global-statement
        self.radius_output_messages = Queue()  # pylint: disable=global-statement

    def test_successful_managed_port_smoke(self):
        port_id = MacAddress.from_string('02:42:ac:17:00:6f')
        self.managed_port = ManagedPort(port_id, self.logger.name, self.timer_scheduler,
                                        self.eap_output_messages,
                                        self.radius_output_messages)
        self.assertIsNotNone(self.managed_port)

    def test_successful_managed_port_change_status(self):
        self.test_successful_managed_port_smoke()

        current_status = self.managed_port.port_status
        self.managed_port.port_status = not current_status
        self.assertIsNot(self.managed_port.port_status, current_status,
                         "Managed Port unable to change status")

    # TODO Add tests:
    #  test_successful_managed_port_change_status_calls_state_machine
    #  test_successful_managed_port_start_identity_requests
    #  test_successful_managed_port_stop_identity_requests

# Test chewie_send_preemptive_identity_requests when port is down
# test reauth_port
