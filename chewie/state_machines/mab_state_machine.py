"""Loosely based on RFC4137 'EAP State Machines' with some interpretation"""
from transitions import Machine, State
from chewie.event import EventMessageReceived, EventRadiusMessageReceived
from chewie.utils import get_logger, log_method, RadiusQueueMessage
from chewie.radius import RadiusAccessAccept, RadiusAccessReject


class MacAuthenticationBypassStateMachine:

    DEFAULT_SESSION_TIMEOUT = 3600  # Number of Seconds

    NO_STATE = "NO_STATE"
    DISABLED = "DISABLED"

    MAB_INIT = "MAB_INIT"
    AAA_SEND_REQUEST = "AAA_SEND_REQUEST"
    AAA_DISCARD = "AAA_DISCARD"
    AAA_RETRANSMIT = "AAA_RETRANSMIT"
    AAA_SUCCESS = "AAA_SUCCESS"
    AAA_FAILURE = "AAA_FAILURE"
    AAA_TIMEOUT_FAILURE = "AAA_TIMEOUT_FAILURE"

    AAA_RECEIVED = "AAA_RECEIVED"
    AAA_REQUEST = "AAA_REQUEST"
    AAA_IDLE = "AAA_IDLE"
    AAA_RESPONSE = "AAA_RESPONSE"

    STATES = [State(NO_STATE, 'mab_reset_state'),
              State(DISABLED, 'mab_disabled_state'),
              State(MAB_INIT, 'mab_init_state'),
              State(AAA_REQUEST, 'aaa_request_state'),
              State(AAA_SEND_REQUEST, 'aaa_send_request_state'),
              State(AAA_IDLE, 'aaa_idle_state'),
              State(AAA_RESPONSE, 'aaa_response_state'),
              State(AAA_SUCCESS, 'aaa_success_state'),
              State(AAA_FAILURE, 'aaa_failure_state'),
              State(AAA_RETRANSMIT, 'aaa_retransmit_state'),
              State(AAA_TIMEOUT_FAILURE, 'aaa_timeout_failure_state'),
              ]

    TRANSITIONS = [
        {'trigger': 'process', 'source': '*', 'dest': DISABLED,
         'unless': ['is_port_enabled']},
        {'trigger': 'process', 'source': DISABLED, 'dest': MAB_INIT,
         'conditions': ['is_port_enabled']},
        {'trigger': 'process', 'source': NO_STATE, 'dest': MAB_INIT,
         'conditions': ['is_eap_restart']},
        {'trigger': 'process', 'source': MAB_INIT, 'dest': AAA_REQUEST},
        {'trigger': 'process', 'source': AAA_REQUEST, 'dest': AAA_IDLE},
        {'trigger': 'process', 'source': AAA_IDLE, 'dest': AAA_TIMEOUT_FAILURE,
         'conditions': ['is_aaa_timeout']},
        {'trigger': 'process', 'source': AAA_IDLE, 'dest': AAA_RESPONSE,
         'conditions': ['is_aaa_resp']},
        {'trigger': 'process', 'source': AAA_RESPONSE, 'dest': AAA_FAILURE,
         'conditions': ['is_aaa_fail']},
        {'trigger': 'process', 'source': AAA_RESPONSE, 'dest': AAA_SUCCESS,
         'conditions': ['is_aaa_success']},
        ]

    # State Variables
    port_enabled = False
    eap_restart = False
    aaa_timeout = False
    aaa_resp = False
    aaa_fail = False
    aaa_success = False

    aaa_response_data = None
    aaa_request_data = None

    def is_port_enabled(self):
        return self.port_enabled

    def is_eap_restart(self):
        return self.eap_restart

    def is_aaa_timeout(self):
        return self.aaa_timeout

    def is_aaa_resp(self):
        return self.aaa_resp

    def is_aaa_fail(self):
        return self.aaa_fail

    def is_aaa_success(self):
        return self.aaa_success

    def __init__(self, eap_output_queue, radius_output_queue, src_mac, timer_scheduler,
                 auth_handler, failure_handler, logoff_handler, log_prefix):
        """

        Args:
            auth_handler (callable): callable that takes input of src_mac. Called on EAP-Success.
            eap_output_queue (Queue): where to put Messages to send to supplicant
            failure_handler (callable): callable that takes input of src_mac. Called on EAP-Failure.
            logoff_handler (callable): callable that takes input of src_mac. Called on EAP-Logoff.
            radius_output_queue (Queue): where to put Messages to send to AAA server
            src_mac (MacAddress): MAC address this statemachine (sm) belongs to.
            timer_scheduler (Scheduler): where to put timer events. (useful for Retransmits)
        """
        self.eap_output_messages = eap_output_queue
        self.radius_output_messages = radius_output_queue
        self.src_mac = src_mac
        self.timer_scheduler = timer_scheduler
        self.auth_handler = auth_handler
        self.failure_handler = failure_handler
        self.logoff_handler = logoff_handler
        self.sent_count = 0
        self.set_timer = None
        self.machine = Machine(model=self, states=MacAuthenticationBypassStateMachine.STATES,
                               transitions=MacAuthenticationBypassStateMachine.TRANSITIONS,
                               queued=True,
                               initial=MacAuthenticationBypassStateMachine.NO_STATE)

        self.logger = get_logger(log_prefix)

        # probably not needed
        self.radius_state_attribute = None
        self.aaa_resp_data = None
        self.eap_restart = True
        self.session_timeout = self.DEFAULT_SESSION_TIMEOUT
        self.port_id_mac = None

    def mab_init_state(self):
        self.eap_restart = False
        return None

    def reset_variable(self):
        self.aaa_timeout = False
        self.aaa_resp = False
        self.aaa_fail = False
        self.aaa_success = False
        self.aaa_response_data = None
        self.aaa_request_data = None


    def event(self, event):
        """Processes an event.
        """
        self.logger.info('start state: %s', self.state)
        self.reset_variable()



        # Process Decisions
        if isinstance(event, EventMessageReceived):
            self.event_message_received(event)
        else:
            self.logger.error('MAB State Machine error. Incorrect event received. %s', event.__dict__)

        self.handle_message_received()

        # Process Information

        if self.aaa_success:
            self.handle_success()

        if self.aaa_fail:
            self.logger.info('Authentication Failed: MAC is not approved for MAB %s', self.src_mac)
            self.handle_failure()

        self.logger.info('end state: %s', self.state)

    def handle_success(self):
        self.logger.info("Successful MAB hitting Handle Success")
        self.auth_handler(self.src_mac, str(self.port_id_mac), self.session_timeout, None, None)

    def handle_failure(self):
        self.logger.info("Successful MAB hit failure")
        self.failure_handler(self.src_mac, str(self.port_id_mac))

    def handle_message_received(self):
        """Main state machine loop"""
        last_state = None
        while self.state != last_state:
            last_state = self.state
            self.process()  # pylint: disable=no-member # pytype: disable=attribute-error

    def event_message_received(self, event):
        #TODO replace with non-bound mac
        if event.port_id:
            self.port_id_mac = event.port_id

        if isinstance(event, EventRadiusMessageReceived):
            self.process_radius_message(event)
        else:
            self.process_ethernet_frame(event)

    def process_ethernet_frame(self, event):
        port_id = event.port_id
        ethernet_packet = event.message
        src_mac = ethernet_packet.src_mac

        # Build the RADIUS Packet and send
        self.logger.info('outputing radius mab')

        self.radius_output_messages.put_nowait(
            RadiusQueueMessage(src_mac, src_mac, src_mac,
            self.radius_state_attribute, port_id))

        self.sent_count += 1
        # self.set_timer(self.RADIUS_RETRANSMIT_TIMEOUT)

    def process_radius_message(self, event):
        self.aaa_resp = True
        self.logger.debug('radius attributes %s', event.attributes)
        self.logger.debug('MAB State Machine ev.msg: %s', self.aaa_resp_data)
        if isinstance(event.message, RadiusAccessAccept):
                self.logger.debug("mab - aaaSuccess")
                self.aaa_success = True
        elif isinstance(event.message, RadiusAccessReject):
                self.logger.debug("mab - aaaFail")
                self.aaa_fail = True
        else:
            raise Exception("Unexpected Packet Type in MAB state Machine: %s" % event.__dict__)

        self.logger.debug('radius event %s', event.__dict__)

    #TODO
    def is_in_progress(self):
        return True

    def is_success(self):
        return self.aaa_success
    # States
    @log_method
    def mab_reset_state(self):
        pass

    @log_method
    def mab_disabled_state(self):
        pass

    @log_method
    def aaa_request_state(self):
        pass

    @log_method
    def aaa_send_request_state(self):
        pass

    @log_method
    def aaa_idle_state(self):
        pass

    @log_method
    def aaa_response_state(self):
        pass

    @log_method
    def aaa_success_state(self):
        pass

    @log_method
    def aaa_failure_state(self):
        pass

    @log_method
    def aaa_retransmit_state(self):
        pass

    @log_method
    def aaa_timeout_failure_state(self):
        pass




