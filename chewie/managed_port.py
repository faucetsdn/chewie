"""This module is used to represent a single 802.1x Port"""
from chewie.utils import get_logger, EapQueueMessage, get_random_id
from chewie.mac_address import MacAddress
from chewie.event import EventPortStatusChange
from chewie.message_parser import IdentityMessage
from chewie.eap import Eap


class ManagedPort:
    """This class is used to represent a single 802.1x Port"""
    DEFAULT_PORT_UP_IDENTITY_REQUEST_WAIT_PERIOD = 20
    DEFAULT_PREEMPTIVE_IDENTITY_REQUEST_INTERVAL = 60
    PAE_GROUP_ADDRESS = MacAddress.from_string("01:80:C2:00:00:03")

    def __init__(self, port_id, log_prefix, timer_scheduler, eap_output_messages,
                 radius_output_messages):
        self.port_id = port_id
        self.logger = get_logger(log_prefix)
        self.supplicant_output_messages = eap_output_messages
        self.radius_output_messages = radius_output_messages

        self.state_machines = {}  # mac : state_machine
        self.current_preemtive_eapol_id = None
        self.port_status = False  # port_id: status (true=up, false=down)
        self.identity_job = None  # timerJob
        self.session_job = None   # timerJob
        self.timer_scheduler = timer_scheduler

    @property
    def status(self):
        """
        Returns the current status of the port.
            True is up
            False is down
        """
        return self.port_status

    @status.setter
    def status(self, value):
        """
        Send status of a port at port_id
        Args:
            port_id ():
            status ():
        """
        self.port_status = value

        # Trigger Subscribers
        for _, state_machine in self.state_machines.items():
            event = EventPortStatusChange(value)
            state_machine.event(event)

        if not value:
            self.state_machines.clear()

    @property
    def clients(self):
        """Returns a list of all managed clients that are attached to this port"""
        return [(self.port_id, mac) for mac in self.state_machines.items()]

    def stop_identity_requests(self):
        """Stop sending Preemptive Identitity Requests"""
        if self.identity_job:
            self.identity_job.cancel()

        self.current_preemtive_eapol_id = None

    def start_identity_requests(self):
        """Start Sending Preemptive Identity Requests"""
        self.identity_job = self.timer_scheduler.call_later(
            self.DEFAULT_PORT_UP_IDENTITY_REQUEST_WAIT_PERIOD,
            self.send_preemptive_identity_request)

    def send_preemptive_identity_request(self):
        """
        If there is no active (in progress, or in state success(2)) supplicant send out the
        preemptive identity request message.
        """
        if not self.port_status:
            self.logger.debug(
                'cant send output on port %s is down', self.port_id)
            return

        self.logger.debug("Sending Identity Request on port %s", self.port_id)
        # schedule next request.
        self.identity_job = self.timer_scheduler.call_later(
            self.DEFAULT_PREEMPTIVE_IDENTITY_REQUEST_INTERVAL,
            self.send_preemptive_identity_request)

        self._send_identity_request()

    def _send_identity_request(self):
        """
        Message (EAP Identity Request) that notifies supplicant that port is using 802.1X
        Args:
            port_id (str):

        """
        _id = get_random_id()
        self.current_preemtive_eapol_id = _id
        data = IdentityMessage(self.PAE_GROUP_ADDRESS, _id, Eap.REQUEST, "")
        self.supplicant_output_messages.put_nowait(
            EapQueueMessage(data, self.PAE_GROUP_ADDRESS, MacAddress.from_string(self.port_id)))
        return _id

    def start_port_session(self, period, src_mac):
        """Start a port session"""
        self.session_job = self.timer_scheduler.call_later(
            period,
            self._reauth_port, src_mac)

    def _reauth_port(self, src_mac):
        """
        Send an Identity Request to src_mac, on port_id.
        prompting the supplicant to re authenticate.
        Args:
            src_mac (MacAddress):
            port_id (str):
        """
        state_machine = self.state_machines.get(str(src_mac), None)

        if state_machine and state_machine.is_success():
            self.logger.info(
                'reauthenticating src_mac: %s on port: %s', src_mac, self.port_id)
            self.start_identity_requests()

        elif state_machine is None:
            self.logger.debug('not reauthing. state machine on port: %s, mac: %s is none',
                              self.port_id,
                              src_mac)
        else:
            self.logger.debug("not reauthing, authentication is not in success(2) (state: %s)'",
                              state_machine.state)
