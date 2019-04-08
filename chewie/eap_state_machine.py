"""Loosely based on RFC4137 'EAP State Machines' with some interpretation"""
import random

from transitions import Machine, State

from chewie.eap import Eap
from chewie.event import EventMessageReceived, EventRadiusMessageReceived, EventTimerExpired, \
    EventPortStatusChange, EventSessionTimeout
from chewie.message_parser import SuccessMessage, FailureMessage, EapolStartMessage, \
    IdentityMessage, EapolLogoffMessage, EapMessage
from chewie.radius_attributes import FilterId, SessionTimeout, TunnelPrivateGroupID
from chewie.utils import get_logger, log_method, RadiusQueueMessage, EapQueueMessage


class Policy:
    """Fleshed out enough to support passthrough mode."""

    @staticmethod
    def get_next_method(eap_resp_data):
        # TODO Probably should do something else
        if isinstance(eap_resp_data, EapolStartMessage):
            return "IDENTITY"
        return "IDENTITY"
        # return "NOTIFICATION"

    @staticmethod
    def get_decision(eap_resp_data):
        # TODO if not offloading return success/failure/Continue
        if eap_resp_data is None or isinstance(eap_resp_data, EapolStartMessage):
            return Decision.CONTINUE
        return Decision.PASSTHROUGH

    @staticmethod
    def update():
        # TODO actually do something?
        pass


class MethodState:
    # pylint: disable=too-few-public-methods
    CONTINUE = "CONTINUE"
    END = "END"
    PROPOSED = "PROPOSED"
    IDENTITY = "IDENTITY"
    NOTIFICATION = "NOTIFICATION"
    NAK = "NAK"
    EXPANDED_NAK = "EXPANDED_NAK"


class Decision:
    # pylint: disable=too-few-public-methods
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    CONTINUE = "CONTINUE"
    PASSTHROUGH = "PASSTHROUGH"


class MPassthrough:
    """M = Method, so if we wanted to do MD5 locally (not passthrough), we'd
    Have class MMD5 with it's own implementation of the methods below"""

    done = False
    src_mac = None

    def check(self, eap_resp_data):  # pylint: disable=unused-argument
        """
        Args:
             eap_resp_data (Message):
        Returns:
            True if packet should be ignored. otherwise False if packet is good.
        """
        # TODO check the *integrity* of the packet.
        #  The IDs already match (done on entry to INTEGRITY_CHECK state)
        return False

    def process(self, eap_resp_data):
        if isinstance(eap_resp_data, IdentityMessage):
            self.done = True

    def init(self, src_mac):
        self.src_mac = src_mac

    def reset(self):
        self.done = False

    def is_done(self):
        return self.done

    def get_timeout(self):
        return 1

    def get_key(self):
        return None

    def build_req(self, current_id):
        return IdentityMessage(self.src_mac, current_id, Eap.REQUEST, "")


class FullEAPStateMachine:
    """Based on RFC 4137 section 7 (EAP Full Authenticator).
    Only acts in passthrough mode (no local method support).
    """

    # non RFC 4137 variables/CONSTANTs
    DEFAULT_TIMEOUT = 5  # Number of Seconds
    DEFAULT_SESSION_TIMEOUT = 3600  # Number of Seconds

    state = None
    eap_output_messages = None
    src_mac = None
    # TODO can use dst_mac to verify where packet came from more thoroughly
    port_id_mac = None
    radius_state_attribute = None  # the last state from radius server
    sent_count = 0
    session_timeout_job = None

    session_timeout = DEFAULT_SESSION_TIMEOUT
    radius_tunnel_private_group_id = None
    filter_id = None

    machine = None

    NO_STATE = "NO_STATE"
    DISABLED = "DISABLED"
    INITIALIZE = "INITIALIZE"
    IDLE = "IDLE"
    RECEIVED = "RECEIVED"
    INTEGRITY_CHECK = "INTEGRITY_CHECK"
    METHOD_RESPONSE = "METHOD_RESPONSE"
    METHOD_REQUEST = "METHOD_REQUEST"
    PROPOSE_METHOD = "PROPOSED_METHOD"
    SELECT_ACTION = "SELECT_ACTION"
    SEND_REQUEST = "SEND_REQUEST"
    DISCARD = "DISCARD"
    NAK = "NAK"
    RETRANSMIT = "RETRANSMIT"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    TIMEOUT_FAILURE = "TIMEOUT_FAILURE"

    INITIALIZE_PASSTRHOUGH = "INITIALIZE_PASSTHROUGH"
    IDLE2 = "IDLE2"
    RECEIVED2 = "RECEIVED2"
    AAA_REQUEST = "AAA_REQUEST"
    AAA_IDLE = "AAA_IDLE"
    AAA_RESPONSE = "AAA_RESPONSE"
    SEND_REQUEST2 = "SEND_REQUEST2"
    DISCARD2 = "DISCARD2"
    RETRANSMIT2 = "RETRANSMIT2"
    SUCCESS2 = "SUCCESS2"
    FAILURE2 = "FAILURE2"
    TIMEOUT_FAILURE2 = "TIMEOUT_FAILURE2"

    # Non RFC 4137 state, when logoff message received sm goes here.
    LOGOFF = "LOGOFF"
    LOGOFF2 = "LOGOFF2"

    STATES = [State(NO_STATE, 'reset_state'),
              State(DISABLED, 'disabled_state'),
              State(INITIALIZE, 'initialize_state'),
              State(IDLE, 'idle_state'),
              State(RECEIVED, 'received_state'),
              State(INTEGRITY_CHECK, 'integrity_check_state'),
              State(METHOD_RESPONSE, 'method_response_state'),
              State(METHOD_REQUEST, 'method_request_state'),
              State(PROPOSE_METHOD, 'propose_method_state'),
              State(SELECT_ACTION, 'select_action_state'),
              State(SEND_REQUEST, 'send_request_state'),
              State(DISCARD, 'discard_state'),
              State(NAK, 'nak_state'),
              State(RETRANSMIT, 'retransmit_state'),
              State(SUCCESS, 'success_state'),
              State(FAILURE, 'failure_state'),
              State(TIMEOUT_FAILURE, 'timeout_failure_state'),
              State(INITIALIZE_PASSTRHOUGH, 'initialize_passthrough_state'),
              State(IDLE2, 'idle2_state'),
              State(RECEIVED2, 'received2_state'),
              State(AAA_IDLE, 'aaa_idle_state'),
              State(AAA_REQUEST, 'aaa_request_state'),
              State(AAA_RESPONSE, 'aaa_response_state'),
              State(SEND_REQUEST2, 'send_request2_state'),
              State(DISCARD2, 'discard2_state'),
              State(RETRANSMIT2, 'retransmit2_state'),
              State(SUCCESS2, 'success2_state'),
              State(FAILURE2, 'failure2_state'),
              State(TIMEOUT_FAILURE2, 'timeout_failure2_state'),
              State(LOGOFF, 'logoff_state'),
              State(LOGOFF2, 'logoff2_state')
              ]

    TRANSITIONS = [{'trigger': 'process', 'source': '*', 'dest': DISABLED,
                    'unless': ['is_port_enabled']},
                   {'trigger': 'process', 'source': '*', 'dest': INITIALIZE,
                    'conditions': ['is_port_enabled',
                                   'is_eap_restart']},
                   {'trigger': 'process', 'source': DISABLED, 'dest': NO_STATE,
                    'conditions': ['is_port_enabled']},
                   {'trigger': 'process', 'source': INITIALIZE, 'dest': SELECT_ACTION},
                   {'trigger': 'process', 'source': SELECT_ACTION, 'dest': PROPOSE_METHOD,
                    'unless': ['is_decision_failure',
                               'is_decision_passthrough',
                               'is_decision_success']},
                   {'trigger': 'process', 'source': SELECT_ACTION, 'dest': FAILURE,
                    'conditions': ['is_decision_failure']},
                   {'trigger': 'process', 'source': SELECT_ACTION, 'dest': SUCCESS,
                    'conditions': ['is_decision_success']},
                   {'trigger': 'process', 'source': SELECT_ACTION, 'dest': INITIALIZE_PASSTRHOUGH,
                    'conditions': ['is_decision_passthrough']},
                   {'trigger': 'process', 'source': PROPOSE_METHOD, 'dest': METHOD_REQUEST},
                   {'trigger': 'process', 'source': METHOD_REQUEST, 'dest': SEND_REQUEST},
                   {'trigger': 'process', 'source': SEND_REQUEST, 'dest': IDLE},
                   {'trigger': 'process', 'source': IDLE, 'dest': RETRANSMIT,
                    'conditions': ['is_retrans_while_equal_0']},
                   {'trigger': 'process', 'source': IDLE, 'dest': RECEIVED,
                    'conditions': ['is_eap_resp']},
                   {'trigger': 'process', 'source': RETRANSMIT, 'dest': TIMEOUT_FAILURE,
                    'conditions': ['is_retrans_count_greater_max_retrans']},
                   {'trigger': 'process', 'source': RETRANSMIT, 'dest': IDLE,
                    'unless': ['is_retrans_count_greater_max_retrans']},
                   {'trigger': 'process', 'source': RECEIVED, 'dest': NAK,
                    'conditions': ['is_enter_nak']},
                   {'trigger': 'process', 'source': RECEIVED, 'dest': INTEGRITY_CHECK,
                    'conditions': ['is_enter_integrity_check']},
                   {'trigger': 'process', 'source': RECEIVED, 'dest': DISCARD,
                    'unless': ['is_enter_nak', 'is_enter_integrity_check']},
                   {'trigger': 'process', 'source': DISCARD, 'dest': IDLE},
                   {'trigger': 'process', 'source': NAK, 'dest': SELECT_ACTION},
                   {'trigger': 'process', 'source': INTEGRITY_CHECK, 'dest': DISCARD,
                    'conditions': ['is_ignore']},
                   {'trigger': 'process', 'source': INTEGRITY_CHECK, 'dest': METHOD_RESPONSE,
                    'unless': ['is_ignore']},
                   {'trigger': 'process', 'source': METHOD_RESPONSE, 'dest': SELECT_ACTION,
                    'conditions': ['is_method_state_equal_end']},
                   {'trigger': 'process', 'source': METHOD_RESPONSE, 'dest': METHOD_REQUEST,
                    'unless': ['is_method_state_equal_end']},

                   {'trigger': 'process', 'source': INITIALIZE_PASSTRHOUGH, 'dest': AAA_IDLE,
                    'conditions': ['is_current_id_none']},
                   {'trigger': 'process', 'source': INITIALIZE_PASSTRHOUGH, 'dest': AAA_REQUEST,
                    'unless': ['is_current_id_none']},
                   {'trigger': 'process', 'source': AAA_REQUEST, 'dest': AAA_IDLE},
                   {'trigger': 'process', 'source': AAA_IDLE, 'dest': TIMEOUT_FAILURE2,
                    'conditions': ['is_aaa_timeout']},
                   {'trigger': 'process', 'source': AAA_IDLE, 'dest': FAILURE2,
                    'conditions': ['is_aaa_fail']},
                   {'trigger': 'process', 'source': AAA_IDLE, 'dest': SUCCESS2,
                    'conditions': ['is_aaa_success']},
                   {'trigger': 'process', 'source': AAA_IDLE, 'dest': AAA_RESPONSE,
                    'conditions': ['is_aaa_eap_req']},
                   {'trigger': 'process', 'source': AAA_IDLE, 'dest': DISCARD2,
                    'conditions': ['is_aaa_eap_no_req']},
                   {'trigger': 'process', 'source': DISCARD2, 'dest': IDLE2},
                   {'trigger': 'process', 'source': AAA_RESPONSE, 'dest': SEND_REQUEST2},
                   {'trigger': 'process', 'source': SEND_REQUEST2, 'dest': IDLE2},
                   {'trigger': 'process', 'source': IDLE2, 'dest': RETRANSMIT2,
                    'conditions': ['is_retrans_while_equal_0']},
                   {'trigger': 'process', 'source': IDLE2, 'dest': RECEIVED2,
                    'conditions': ['is_eap_resp']},
                   {'trigger': 'process', 'source': RETRANSMIT2, 'dest': TIMEOUT_FAILURE2,
                    'conditions': ['is_retrans_count_greater_max_retrans']},
                   {'trigger': 'process', 'source': RETRANSMIT2, 'dest': IDLE2,
                    'unless': ['is_retrans_count_greater_max_retrans']},
                   {'trigger': 'process', 'source': RECEIVED2, 'dest': AAA_REQUEST,
                    'conditions': ['is_rx_resp', 'is_resp_id_equal_current_id']},
                   {'trigger': 'process', 'source': RECEIVED2, 'dest': DISCARD2,
                    'conditions': ['is_enter_discard2']},

                   {'trigger': 'process', 'source': SUCCESS, 'dest': LOGOFF,
                    'conditions': ['is_logoff']},
                   {'trigger': 'process', 'source': SUCCESS2, 'dest': LOGOFF2,
                    'conditions': ['is_logoff']},
                   ]

    # RFC 4137
    MAX_RETRANS = 5  # Configurable  max for retransmissions before aborting.

    # Variables (AAA Interface to Full Authenticator)
    aaa_eap_req = None        # bool
    aaa_eap_no_req = None      # bool
    aaa_success = None       # bool
    aaa_fail = None          # bool
    aaa_eap_req_data = None    # EAP packet
    aaa_eap_key_data = None    # EAP Key
    aaa_eap_key_available = None   # bool
    aaa_method_timeout = None     # integer or NONE

    # Variables (Full Authenticator to AAA Interface)
    aaa_eap_resp = None       # bool
    aaa_eap_resp_data = None   # EAP Packet
    aaa_identity = None      # EAP Packet
    aaa_timeout = None      # bool

    # Stand-Alone Authenticator State Machine Local Variables
    current_method = None    # EAP type
    current_id = None        # integer
    method_state = None      # enum
    retrans_count = None     # integer
    last_req_data = None      # EAP packet
    method_timeout = None    # integer
    logoff = None           # bool
    # Non RFC 4137
    override_current_id = None

    # Lower Later  to Stand-Alone Authenticator
    eap_resp = None      # bool
    eap_resp_data = None  # EAP Packet
    port_enabled = None  # bool
    retrans_while = None     # integer
    eap_restart = None   # bool
    eap_srtt = None      # integer
    eap_rttvar = None    # integer

    # Stand-Alone authenticator to Lower Layer
    eap_req = None       # bool
    eap_no_req = None     # bool
    eap_success = None   # bool
    eap_fail = None      # bool
    eap_timeout = None   # bool
    eap_req_data = None   # EAP Packet
    eap_key_data = None   # EAP Key
    eap_key_available = None  # bool
    # Non RFC 4137
    eap_logoff = None    # bool

    # short term local variables (not maintained between packets)
    rx_resp = None
    resp_id = None
    resp_method = None
    ignore = None
    decision = None

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

        self.machine = Machine(model=self, states=FullEAPStateMachine.STATES,
                               transitions=FullEAPStateMachine.TRANSITIONS,
                               queued=True,
                               initial=FullEAPStateMachine.NO_STATE)

        # TODO dynamically assign this or make a way to give it multiple methods
        # and self.m is the one currently in use.
        # if we want to deal with each method locally.
        self.m = MPassthrough()  # pylint: disable=invalid-name
        self.logger = get_logger(log_prefix)

    def is_eap_restart(self):
        return self.eap_restart

    def is_port_enabled(self):
        return self.port_enabled

    def is_decision_failure(self):
        return self.decision == Decision.FAILURE

    def is_decision_success(self):
        return self.decision == Decision.SUCCESS

    def is_decision_passthrough(self):
        return self.decision == Decision.PASSTHROUGH

    def is_retrans_while_equal_0(self):
        return self.retrans_while == 0

    def is_eap_resp(self):
        return self.eap_resp

    def is_retrans_count_greater_max_retrans(self):
        return self.retrans_count > self.MAX_RETRANS

    def is_enter_nak(self):
        return self.rx_resp and self.resp_id == self.current_id \
               and (self.resp_method in (MethodState.NAK, MethodState.EXPANDED_NAK)) \
               and self.method_state == MethodState.PROPOSED

    def is_enter_integrity_check(self):
        return self.rx_resp and self.resp_id == self.current_id \
               and self.resp_method == self.current_method

    def is_ignore(self):
        return self.ignore

    def is_method_state_equal_end(self):
        return self.method_state == MethodState.END

    def is_current_id_none(self):
        return self.current_id is None

    def is_aaa_timeout(self):
        return self.aaa_timeout

    def is_aaa_fail(self):
        return self.aaa_fail

    def is_aaa_success(self):
        return self.aaa_success

    def is_aaa_eap_req(self):
        return self.aaa_eap_req

    def is_aaa_eap_no_req(self):
        return self.aaa_eap_no_req

    def is_rx_resp(self):
        return self.rx_resp is not None

    def is_resp_id_equal_current_id(self):
        return self.resp_id == self.current_id

    def is_enter_discard2(self):
        return self.rx_resp is None or self.resp_id != self.current_id

    def is_logoff(self):
        return self.logoff

    def get_id(self):
        """Determines the identifier value chosen by the AAA server for the current EAP request.
         The return value is an integer."""
        return self.eap_req_data.message_id

    def calculate_timeout(self, retrans_count, eap_srtt, eap_rttvar, method_timeout):  # pylint: disable=unused-argument
        """https://tools.ietf.org/html/rfc3748#section-4.3
        Args:
            retrans_count:
            eap_srtt:
            eap_rttvar:
            method_timeout:

        Returns:
            Milliseconds"""
        # TODO actually implement.
        return self.DEFAULT_TIMEOUT

    def parse_eap_resp(self):
        """
        Returns:
            int, int, EAP Type (str)
        """
        eap = self.eap_resp_data
        resp_method = None

        _id = eap.message_id

        if isinstance(eap, IdentityMessage):
            resp_method = MethodState.IDENTITY
        # RFC 4137 #section 5.4 says eap.code should actually be a bool
        eap_code = getattr(eap, 'code', None)
        return eap_code, _id, resp_method

    def build_success(self):
        """Creates an EAP Sucecss Pakcet. Returns an EAP packet"""
        return SuccessMessage(self.src_mac, self.current_id)

    def build_failure(self):
        """Creates an EAP Failure Packet. Returns an EAP packet"""
        return FailureMessage(self.src_mac, self.current_id)

    def next_id(self):
        """Determines the next identifier value to use, based on the previous one.
        Returns:
            integer"""
        if self.current_id is None:
            # I'm assuming we cant have ids wrap around in the same series.
            #  so the 200 provides a large buffer.
            return random.randint(0, 200)
        _id = self.current_id + 1
        # not tested
        if _id > 255:
            return random.randint(0, 200)
        return _id

    @log_method
    def disabled_state(self):
        """The authenticator is disabled until the port is enabled by the lower layer"""
        # DISABLED does not do anything.
        pass

    @log_method
    def propose_method_state(self):
        self.current_method = Policy.get_next_method(self.eap_resp_data)
        self.m.init(self.src_mac)
        if self.current_method == "IDENTITY" or self.current_method == "NOTIFICATION":
            self.method_state = MethodState.CONTINUE
        else:
            self.method_state = MethodState.PROPOSED

    @log_method
    def failure_state(self):
        self.eap_req_data = self.build_failure()
        self.eap_fail = True

    @log_method
    def timeout_failure_state(self):
        self.eap_timeout = True

    @log_method
    def success_state(self):
        self.eap_req_data = self.build_success()
        if self.eap_key_data:
            self.eap_key_available = True
        self.eap_success = True

    @log_method
    def initialize_state(self):
        """Initializes variables when the state machine is activated"""
        self.current_id = None
        if self.override_current_id:
            self.current_id = self.override_current_id
        self.override_current_id = None
        self.eap_success = False
        self.eap_fail = False
        self.eap_timeout = False
        self.eap_key_data = None
        self.eap_restart = False

        self.eap_logoff = False

        self.radius_state_attribute = None

    @log_method
    def idle_state(self):
        """The state machine spends most of its time here, waiting for something to happen"""
        self.retrans_while = self.calculate_timeout(self.retrans_count, self.eap_srtt,
                                                    self.eap_rttvar, self.method_timeout)

    @log_method
    def received_state(self):
        """This state is entered when an EAP packet is received. The packet header is parsed here"""
        self.rx_resp, self.resp_id, self.resp_method = self.parse_eap_resp()

    @log_method
    def select_action_state(self):
        self.decision = Policy.get_decision(self.eap_resp_data)

    @log_method
    def method_response_state(self):
        self.m.process(self.eap_resp_data)
        if self.m.is_done():
            Policy.update()
            self.eap_key_data = self.m.get_key()
            self.method_state = MethodState.END
        else:
            self.method_state = MethodState.CONTINUE

    @log_method
    def discard_state(self):
        self.eap_resp = False
        self.eap_no_req = True

    @log_method
    def integrity_check_state(self):
        self.ignore = self.m.check(self.eap_resp_data)

    @log_method
    def nak_state(self):
        self.m.reset()
        Policy.update()

    @log_method
    def retransmit_state(self):
        self.retrans_count += 1
        if self.retrans_count <= self.MAX_RETRANS:
            self.eap_req_data = self.last_req_data
            self.eap_req = True

    @log_method
    def send_request_state(self):
        self.retrans_count = 0
        self.last_req_data = self.eap_req_data
        self.eap_resp = False
        self.eap_req = True

    @log_method
    def method_request_state(self):
        self.current_id = self.next_id()
        self.eap_req_data = self.m.build_req(self.current_id)
        self.method_timeout = self.m.get_timeout()

    @log_method
    def initialize_passthrough_state(self):
        self.aaa_eap_resp = None

    @log_method
    def idle2_state(self):
        self.retrans_while = self.calculate_timeout(self.retrans_count, self.eap_srtt,
                                                    self.eap_rttvar, self.method_timeout)

    @log_method
    def received2_state(self):
        self.rx_resp, self.resp_id, self.resp_method = self.parse_eap_resp()


    @log_method
    def aaa_request_state(self):
        if self.resp_method == MethodState.IDENTITY:
            self.aaa_identity = self.eap_resp_data
        self.aaa_eap_resp_data = self.eap_resp_data

    @log_method
    def aaa_idle_state(self):
        self.aaa_fail = False
        self.aaa_success = False
        self.aaa_eap_req = False
        self.aaa_eap_no_req = False
        self.aaa_eap_resp = True

    @log_method
    def aaa_response_state(self):
        self.eap_req_data = self.aaa_eap_req_data
        self.current_id = self.get_id()
        self.method_timeout = self.aaa_method_timeout

    @log_method
    def send_request2_state(self):
        self.retrans_count = 0
        self.last_req_data = self.eap_req_data
        self.eap_resp = False
        self.eap_req = True

    @log_method
    def discard2_state(self):
        self.eap_resp = False
        self.eap_no_req = True

    @log_method
    def retransmit2_state(self):
        self.retrans_count += 1
        if self.retrans_count <= self.MAX_RETRANS:
            self.eap_req_data = self.last_req_data
            self.eap_req = True

    @log_method
    def success2_state(self):
        self.eap_req = True
        self.eap_req_data = self.aaa_eap_req_data
        self.eap_key_data = self.aaa_eap_key_data
        self.eap_key_available = self.aaa_eap_key_available
        self.eap_success = True

    @log_method
    def failure2_state(self):
        self.eap_req = True
        self.eap_req_data = self.aaa_eap_req_data
        self.eap_fail = True

    @log_method
    def timeout_failure2_state(self):
        self.eap_timeout = True

    @log_method
    def logoff_state(self):
        self.eap_success = False
        self.eap_logoff = True

    @log_method
    def logoff2_state(self):
        self.eap_success = False
        self.eap_logoff = True

    @log_method
    def reset_state(self):
        self.initialize_state()
        self.aaa_eap_req_data = None
        self.aaa_eap_key_data = None
        self.eap_req_data = None
        self.eap_key_data = None
        self.eap_success = False
        self.aaa_success = False

    def handle_message_received(self):
        """Main state machine loop"""

        self.rx_resp = None
        self.resp_id = None
        self.resp_method = None
        self.ignore = None
        self.decision = None

        last_state = None
        while self.state != last_state:
            last_state = self.state
            self.process()  # pylint: disable=no-member # pytype: disable=attribute-error

    def lower_layer_reset(self):
        """Sets variables that are meant to be set by the lower layer
        RFC4137 5.1.2 (standalone authenticator to Lower Layer)"""
        self.eap_req = False
        self.eap_no_req = False
        self.eap_success = False
        self.eap_fail = False
        self.eap_timeout = False

        self.logoff = False

        self.aaa_eap_resp = False
        self.aaa_timeout = False

    def event(self, event):
        """Processes an event.
        Output is via the eap/radius queue. and again will be of type ***Message.
        Args:
            event: should have message attribute which is of the ***Message types
            (e.g. SuccessMessage, IdentityMessage,...)
        """
        self.lower_layer_reset()
        self.logger.info("full state machine received event: %s", event)
        # 'Lower Layer' shim
        if isinstance(event, EventMessageReceived):
            self.message_event_received(event)

        elif isinstance(event, EventTimerExpired):
            if self.timer_expired_event_received(event):
                return

        elif isinstance(event, EventPortStatusChange):
            self.port_status_event_received(event)
        elif isinstance(event, EventSessionTimeout):
            self.session_timeout_event_received()

        self.handle_message_received()
        self.logger.info('end state: %s', self.state)

        if self.eap_req:
            if (hasattr(self.eap_req_data, 'code') and self.eap_req_data.code == Eap.REQUEST) \
                    or isinstance(self.eap_req_data, (SuccessMessage, FailureMessage)):
                self.logger.info("outputting eap, '%s', src: '%s' port_id: '%s'",
                                 self.eap_req_data, self.src_mac, self.port_id_mac)
                self.eap_output_messages.put_nowait(
                    EapQueueMessage(self.eap_req_data, self.src_mac, self.port_id_mac))
                self.sent_count += 1
                self.set_timer()
            # not tested
            else:
                self.logger.error('cant find code --- %s', self.eap_req_data)
            self.eap_req = False

        if self.aaa_eap_resp and self.aaa_eap_resp_data:
            if self.aaa_eap_resp_data.code == Eap.RESPONSE:
                self.logger.info('outputing radius')
                self.radius_output_messages.put_nowait(
                    RadiusQueueMessage(self.aaa_eap_resp_data, self.src_mac,
                                       self.aaa_identity.identity,
                                       self.radius_state_attribute, self.port_id_mac))

                self.sent_count += 1
                self.set_timer()
            self.aaa_eap_resp = False
        # not tested
        elif self.aaa_eap_resp:
            self.logger.error("aaa_eap_resp is true. but data is false. This should never happen")

        if self.eap_success:
            self.handle_success()

        if self.eap_fail:
            self.logger.info('oh authentication not successful %s', self.src_mac)
            self.failure_handler(self.src_mac, str(self.port_id_mac))

        if self.eap_logoff:
            self.handle_logoff()

    def handle_logoff(self):
        """Notify the logoff callback"""
        self.logger.info('client is logging off %s', self.src_mac)
        self.logoff_handler(self.src_mac, str(self.port_id_mac))
        if self.session_timeout_job:
            self.session_timeout_job.cancel()

    def handle_success(self):
        """Notify the success callback and sets a timer event to expire this session"""
        self.logger.info('Yay authentication successful %s %s',
                         self.src_mac, self.aaa_identity.identity)
        self.auth_handler(self.src_mac, str(self.port_id_mac),
                          self.session_timeout, self.radius_tunnel_private_group_id, self.filter_id)
        self.aaa_eap_resp_data = None

        # new authentication so cancel the old session timeout event
        if self.session_timeout_job:
            self.session_timeout_job.cancel()

        self.session_timeout_job = self.timer_scheduler.call_later(self.session_timeout,
                                                                   self.event,
                                                                   EventSessionTimeout(self))

    def session_timeout_event_received(self):
        """process session timeout event"""
        self.logoff = True

    def port_status_event_received(self, event):
        """Sets variables for the port status change (link up/down) being received.
        Args:
            event (EventPortStatusChange):
        """
        self.port_enabled = event.port_status

    def timer_expired_event_received(self, event):
        """Check if the event has been replied to. and set variables.
        Args:
            event (EventTimerExpired): event to process

        Returns:
            True if this event is being ignored and no further processing is required.
            Otherwise False.
        """
        # TODO Should this still log all ExpiredTimerEvents when none are cancelled?
        self.logger.info("Expired Timer Event Received")
        if self.sent_count == event.sent_count:
            self.logger.debug("processing timer event. haven't received a reply. %s %s",
                              self.sent_count, event.sent_count)

            if self.state == self.AAA_IDLE:
                self.aaa_timeout = True
            if self.state == self.IDLE2 or self.state == self.IDLE:
                self.retrans_while = 0

            return False
        self.logger.debug("ignoring timer event, already received a reply.")
        return True

    def message_event_received(self, event):
        """Sets variables for the Eap message being received.
        Args:
            event (EventMessageReceived): event being processed.
        """
        message = event.message
        self.logger.info('type: %s, message %s ', type(message), message)
        if event.port_id:
            self.port_id_mac = event.port_id

        if isinstance(message, EapolStartMessage) or \
                (self.state in (FullEAPStateMachine.TIMEOUT_FAILURE,
                                FullEAPStateMachine.TIMEOUT_FAILURE2) and
                 isinstance(message, EapMessage) and message.code == Eap.RESPONSE
                ):
            self.eap_restart = True
        elif isinstance(message, EapolLogoffMessage):
            self.logoff = True

        if isinstance(event, EventRadiusMessageReceived):
            self.process_radius_message(event)
        else:
            self.eap_resp_data = message
            self.eap_resp = True

    def process_radius_message(self, event):
        """Process radius message (set and extract radius specific variables)"""
        self.eap_resp_data = None
        self.eap_resp = False
        self.logger.debug('radius attributes %s', event.attributes)
        self.radius_state_attribute = event.state
        self.aaa_eap_req = True
        self.aaa_eap_req_data = event.message
        self.logger.debug('sm ev.msg: %s', self.aaa_eap_req_data)
        if isinstance(self.aaa_eap_req_data, SuccessMessage):
            self.logger.debug("aaaSuccess")
            self.aaa_success = True
        if isinstance(self.aaa_eap_req_data, FailureMessage):
            self.logger.debug("aaaFail")
            self.aaa_fail = True
        self.logger.debug('radius event %s', event.__dict__)
        self.set_vars_from_radius(event.attributes)

    def set_vars_from_radius(self, attributes):
        """
        Set the statemachine variables from attributes received in the radius message.
        If variable does not exist in the radius message, it is reset to the default
        Args:
            attributes (dict):  attributes to be set.
        """
        self.session_timeout = self.DEFAULT_SESSION_TIMEOUT
        self.radius_tunnel_private_group_id = None
        self.filter_id = None

        if attributes:
            self.session_timeout = attributes.get(SessionTimeout.DESCRIPTION,
                                                  self.DEFAULT_SESSION_TIMEOUT)
            self.radius_tunnel_private_group_id = attributes.get(TunnelPrivateGroupID.DESCRIPTION,
                                                                 None)
            self.filter_id = attributes.get(FilterId.DESCRIPTION,
                                                                 None)
            if self.radius_tunnel_private_group_id:
                self.radius_tunnel_private_group_id = self.radius_tunnel_private_group_id.decode('utf-8')
        # TODO could also set filter-id/vlans/acls here.

    def set_timer(self):
        """Sets a timer to trigger a retransmit if no packet received.
        """
        # These messages should not expect a reply, so set the timer.
        if self.state not in [self.SUCCESS, self.SUCCESS2,
                              self.FAILURE, self.FAILURE2,
                              self.TIMEOUT_FAILURE, self.TIMEOUT_FAILURE2]:
            timeout = self.retrans_while
            self.timer_scheduler.call_later(timeout,
                                            self.event,
                                            EventTimerExpired(self, self.sent_count))
            # TODO could cancel the scheduled events when
            # they're no longer needed (i.e. response received)

    def is_in_progress(self):
        return self.state not in [FullEAPStateMachine.LOGOFF, FullEAPStateMachine.LOGOFF2,
                                  FullEAPStateMachine.DISABLED, FullEAPStateMachine.NO_STATE,
                                  FullEAPStateMachine.FAILURE, FullEAPStateMachine.FAILURE2,
                                  FullEAPStateMachine.TIMEOUT_FAILURE,
                                  FullEAPStateMachine.TIMEOUT_FAILURE2,]
                                  # FullEAPStateMachine.SUCCESS, FullEAPStateMachine.SUCCESS2]

    def is_success(self):
        return self.state in [FullEAPStateMachine.SUCCESS, FullEAPStateMachine.SUCCESS2]
