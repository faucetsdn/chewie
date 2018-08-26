"""Loosely based on RFC4137 'EAP State Machines' with some interpretation"""
import random

from chewie.eap import Eap
from chewie.event import EventMessageReceived, EventRadiusMessageReceived, EventTimerExpired, \
    EventPortStatusChange
from chewie.message_parser import SuccessMessage, FailureMessage, EapolStartMessage, \
    IdentityMessage, EapolLogoffMessage
import chewie.utils as utils
from chewie.utils import log_method


class Policy:
    """Fleshed out enough to support passthrough mode."""

    @staticmethod
    def getNextMethod(eapRespData):
        # TODO Probably should do something else
        if isinstance(eapRespData, EapolStartMessage):
            return "IDENTITY"
        return "NOTIFICATION"

    @staticmethod
    def getDecision(eapRespData):
        # TODO if not offloading return success/failure/Continue
        if eapRespData is None or isinstance(eapRespData, EapolStartMessage):
            return Decision.CONTINUE
        return Decision.PASSTHROUGH

    @staticmethod
    def update():
        # TODO actually do something?
        pass


class MethodState:
    CONTINUE = "CONTINUE"
    END = "END"
    PROPOSED = "PROPOSED"
    IDENTITY = "IDENTITY"
    NOTIFICATION = "NOTIFICATION"
    NAK = "NAK"
    EXPANDED_NAK = "EXPANDED_NAK"


class Decision:
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    CONTINUE = "CONTINUE"
    PASSTHROUGH = "PASSTHROUGH"


class MPassthrough:
    """M = Method, so if we wanted to do MD5 locally (not passthrough), we'd
    Have class MMD5 with it's own implementation of the methods below"""

    done = False
    src_mac = None

    def check(self, eapRespData):
        """
        Args:
             eapRespData (Message):
        Returns:
            True if packet should be ignored. otherwise False if packet is good.
        """
        # TODO check the *integrity* of the packet.
        #  The IDs already match (done on entry to INTEGRITY_CHECK state)
        return False

    def process(self, eapRespData):
        if isinstance(eapRespData, IdentityMessage):
            self.done = True

    def init(self, src_mac):
        self.src_mac = src_mac

    def reset(self):
        self.done = False

    def isDone(self):
        return self.done

    def getTimeout(self):
        return 1

    def getKey(self):
        return None

    def buildReq(self, current_id):
        return IdentityMessage(self.src_mac, current_id, Eap.REQUEST, "")


class FullEAPStateMachine:
    """Based on RFC 4137 section 7 (EAP Full Authenticator).
    Only acts in passthrough mode (no local method support).
    """

    # non RFC 4137 variables/CONSTANTs
    currentState = None
    eap_output_messages = None
    src_mac = None
    radius_state_attribute = None  # the last state from radius server
    sent_count = 0

    DEFAULT_TIMEOUT = 5  # Number of Seconds

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

    # RFC 4137
    MAX_RETRANS = 5  # Configurable  max for retransmissions before aborting.

    # Variables (AAA Interface to Full Authenticator)
    aaaEapReq = None        # bool
    aaaEapNoReq = None      # bool
    aaaSuccess = None       # bool
    aaaFail = None          # bool
    aaaEapReqData = None    # EAP packet
    aaaEapKeyData = None    # EAP Key
    aaaEapKeyAvailable = None   # bool
    aaaMethodTimeout = None     # integer or NONE

    # Variables (Full Authenticator to AAA Interface)
    aaaEapResp = None       # bool
    aaaEapRespData = None   # EAP Packet
    aaaIdentity = None      # EAP Packet
    aaaTimeout = None      # bool

    # Stand-Alone Authenticator State Machine Local Variables
    currentMethod = None    # EAP type
    currentId = None        # integer
    methodState = None      # enum
    retransCount = None     # integer
    lastReqData = None      # EAP packet
    methodTimeout = None    # integer
    logoff = None           # bool

    # Lower Later  to Stand-Alone Authenticator
    eapResp = None      # bool
    eapRespData = None  # EAP Packet
    portEnabled = None  # bool
    retransWhile = None     # integer
    eapRestart = None   # bool
    eapSRTT = None      # integer
    eapRTTVAR = None    # integer

    # Stand-Alone authenticator to Lower Layer
    eapReq = None       # bool
    eapNoReq = None     # bool
    eapSuccess = None   # bool
    eapFail = None      # bool
    eapTimeout = None   # bool
    eapReqData = None   # EAP Packet
    eapKeyData = None   # EAP Key
    eapKeyAvailable = None  # bool
    # Non RFC 4137
    eapLogoff = None    # bool

    def __init__(self, eap_output_queue, radius_output_queue, src_mac, timer_scheduler,
                 auth_handler):
        """

        Args:
            auth_handler (callable): callable that takes input of src_mac. Called on EAP-Success.
            eap_output_queue (Queue): where to put Messages to send to supplicant
            radius_output_queue (Queue): where to put Messages to send to AAA server
            src_mac (MacAddress): MAC address this statemachine (sm) belongs to.
            timer_scheduler (Scheduler): where to put timer events. (useful for Retransmits)
        """
        self.eap_output_messages = eap_output_queue
        self.radius_output_messages = radius_output_queue
        self.src_mac = src_mac
        self.timer_scheduler = timer_scheduler
        self.auth_handler = auth_handler

        self.currentState = FullEAPStateMachine.NO_STATE
        # TODO dynamically assign this or make a way to give it multiple methods
        # and self.m is the one currently in use.
        # if we want to deal with each method locally.
        self.m = MPassthrough()

        self.logger = utils.get_logger("SM - %s" % self.src_mac)

    def getId(self):
        """Determines the identifier value chosen by the AAA server for the current EAP request.
         The return value is an integer."""
        return self.eapReqData.message_id

    def calculateTimeout(self, retransCount, eapSRTT, eapRTTVAR, methodTimeout):
        """https://tools.ietf.org/html/rfc3748#section-4.3
        Args:
            retransCount:
            eapSRTT:
            eapRTTVAR:
            methodTimeout:

        Returns:
            Milliseconds"""
        # TODO actually implement.
        return self.DEFAULT_TIMEOUT

    def parseEapResp(self):
        """
        Returns:
            int, int, EAP Type (str)
        """
        eap = self.eapRespData
        respMethod = None

        _id = eap.message_id

        if isinstance(eap, IdentityMessage):
            respMethod = MethodState.IDENTITY
        # RFC 4137 #section 5.4 says eap.code should actually be a bool
        return eap.code, _id, respMethod

    def buildSuccess(self):
        """Creates an EAP Sucecss Pakcet. Returns an EAP packet"""
        return SuccessMessage(self.src_mac, self.currentId)

    def buildFailure(self):
        """Creates an EAP Failure Packet. Returns an EAP packet"""
        return FailureMessage(self.src_mac, self.currentId)

    def nextId(self):
        """Determines the next identifier value to use, based on the previous one.
        Returns:
            integer"""
        if self.currentId is None:
            # I'm assuming we cant have ids wrap around in the same series.
            #  so the 200 provides a large buffer.
            return random.randint(0, 200)
        else:
            _id = self.currentId + 1
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
        self.currentMethod = Policy.getNextMethod(self.eapRespData)
        self.m.init(self.src_mac)
        if self.currentMethod == "IDENTITY" or self.currentMethod == "NOTIFICATION":
            self.methodState = MethodState.CONTINUE
        else:
            self.methodState = MethodState.PROPOSED

    @log_method
    def failure_state(self):
        self.eapReqData = self.buildFailure()
        self.eapFail = True

    @log_method
    def success_state(self):
        self.eapReqData = self.buildSuccess()
        if self.eapKeyData:
            self.eapKeyAvailable = True
        self.eapSuccess = True

    @log_method
    def initialize_state(self):
        """Initializes variables when the state machine is activated"""
        self.currentId = None
        self.eapSuccess = False
        self.eapFail = False
        self.eapTimeout = False
        self.eapKeyData = None
        self.eapRestart = False

        self.eapLogoff = False

    @log_method
    def idle_state(self):
        """The state machine spends most of its time here, waiting for something to happen"""
        self.retransWhile = self.calculateTimeout(self.retransCount, self.eapSRTT,
                                                  self.eapRTTVAR, self.methodTimeout)

    @log_method
    def recieved_state(self):
        """This state is entered when an EAP packet is received. The packet header is parsed here"""
        rxResp, respId, respMethod = self.parseEapResp()
        return rxResp, respId, respMethod

    @log_method
    def select_action_state(self):
        decision = Policy.getDecision(self.eapRespData)
        return decision

    @log_method
    def method_response_state(self):
        self.m.process(self.eapRespData)
        if self.m.isDone():
            Policy.update()
            self.eapKeyData = self.m.getKey()
            self.methodState = MethodState.END
        else:
            self.methodState = MethodState.CONTINUE

    @log_method
    def discard_state(self):
        self.eapResp = False
        self.eapNoReq = True

    @log_method
    def integrity_check_state(self):
        ignore = self.m.check(self.eapRespData)
        return ignore

    @log_method
    def nak_state(self):
        self.m.reset()
        Policy.update()

    @log_method
    def retransmit_state(self):
        self.retransCount += 1
        if self.retransCount <= self.MAX_RETRANS:
            self.eapReqData = self.lastReqData
            self.eapReq = True

    @log_method
    def send_request_state(self):
        self.retransCount = 0
        self.lastReqData = self.eapReqData
        self.eapResp = False
        self.eapReq = True

    @log_method
    def method_request_state(self):
        self.currentId = self.nextId()
        self.eapReqData = self.m.buildReq(self.currentId)
        self.methodTimeout = self.m.getTimeout()

    @log_method
    def initialize_passthrough_state(self):
        self.aaaEapResp = None

    @log_method
    def idle2_state(self):
        self.retransWhile = self.calculateTimeout(self.retransCount, self.eapSRTT,
                                                  self.eapRTTVAR, self.methodTimeout)

    @log_method
    def received2_state(self):
        rxResp, respId, respMethod = self.parseEapResp()
        return rxResp, respId, respMethod

    @log_method
    def aaa_request_state(self, respMethod):
        if respMethod == MethodState.IDENTITY:
            self.aaaIdentity = self.eapRespData
        self.aaaEapRespData = self.eapRespData

    @log_method
    def aaa_idle_state(self):
        self.aaaFail = False
        self.aaaSuccess = False
        self.aaaEapReq = False
        self.aaaEapNoReq = False
        self.aaaEapResp = True

    @log_method
    def aaa_response_state(self):
        self.eapReqData = self.aaaEapReqData
        self.currentId = self.getId()
        self.methodTimeout = self.aaaMethodTimeout

    @log_method
    def send_request2_state(self):
        self.retransCount = 0
        self.lastReqData = self.eapReqData
        self.eapResp = False
        self.eapReq = True

    @log_method
    def discard2_state(self):
        self.eapResp = False
        self.eapNoReq = True

    @log_method
    def retransmit2_state(self):
        self.retransCount += 1
        if self.retransCount <= self.MAX_RETRANS:
            self.eapReqData = self.lastReqData
            self.eapReq = True

    @log_method
    def success2_state(self):
        self.eapReq = True
        self.eapReqData = self.aaaEapReqData
        self.eapKeyData = self.aaaEapKeyData
        self.eapKeyAvailable = self.aaaEapKeyAvailable
        self.eapSuccess = True

    @log_method
    def failure2_state(self):
        self.eapReq = True
        self.eapReqData = self.aaaEapReqData
        self.eapFail = True

    @log_method
    def timeout_failure2_state(self):
        self.eapTimeout = True

    @log_method
    def logoff_state(self):
        self.eapSuccess = False
        self.eapLogoff = True

    @log_method
    def logoff2_state(self):
        self.eapSuccess = False
        self.eapLogoff = True

    def handle_message_received(self):
        """Main state machine loop"""

        # RFC 4137 Figure 6
        # the *_state() method is the box.
        # if variable(s) are required by the decision branches
        #  they are returned by the *_state() method,
        # and stored as a local variable for the next iteration of the loop.
        #
        # so execute zzzz_state(), currentState = zzzz_state.
        # next loop iter, currentstate( i.e. zzzz) == zzzz, yyyy_state(), currentState = yyyy

        rxResp = None
        respId = None
        respMethod = None
        ignore = None
        decision = None

        last_state = None

        while self.currentState != last_state:
            last_state = self.currentState
            if not self.portEnabled and self.currentState != FullEAPStateMachine.DISABLED:
                self.disabled_state()
                self.currentState = FullEAPStateMachine.DISABLED

            if self.eapRestart and self.portEnabled:
                self.initialize_state()
                self.currentState = FullEAPStateMachine.INITIALIZE

            if self.currentState == FullEAPStateMachine.INITIALIZE:
                decision = self.select_action_state()
                self.currentState = FullEAPStateMachine.SELECT_ACTION

            if self.currentState == FullEAPStateMachine.DISABLED and self.portEnabled:
                self.initialize_state()
                self.currentState = FullEAPStateMachine.INITIALIZE

            if self.currentState == FullEAPStateMachine.SELECT_ACTION:
                if decision == Decision.SUCCESS:
                    self.success_state()
                    self.currentState = FullEAPStateMachine.SUCCESS
                elif decision == Decision.FAILURE:
                    self.failure_state()
                    self.currentState = FullEAPStateMachine.FAILURE
                elif decision == Decision.PASSTHROUGH:
                    self.initialize_passthrough_state()
                    self.currentState = FullEAPStateMachine.INITIALIZE_PASSTRHOUGH
                else:
                    self.propose_method_state()
                    self.currentState = FullEAPStateMachine.PROPOSE_METHOD

            if self.currentState == FullEAPStateMachine.FAILURE:
                # Do nothing.
                pass

            if self.currentState == FullEAPStateMachine.SUCCESS:
                # RFC 4137 says do nothing from success(2), but we're adding a logoff state.
                # hopefully it will work as intended.
                # Otherwise allow transition to logoff from all states.
                if self.eapLogoff:
                    self.logoff_state()
                    self.currentState = FullEAPStateMachine.LOGOFF

            if self.currentState == FullEAPStateMachine.TIMEOUT_FAILURE:
                # Do nothing.
                pass

            if self.currentState == FullEAPStateMachine.PROPOSE_METHOD:
                self.method_request_state()
                self.currentState = FullEAPStateMachine.METHOD_REQUEST

            if self.currentState == FullEAPStateMachine.METHOD_REQUEST:
                self.send_request_state()
                self.currentState = FullEAPStateMachine.SEND_REQUEST

            if self.currentState == FullEAPStateMachine.SEND_REQUEST:
                self.idle_state()
                self.currentState = FullEAPStateMachine.IDLE

            if self.currentState == FullEAPStateMachine.IDLE:
                if self.retransWhile == 0:
                    self.retransmit_state()
                    self.currentState = FullEAPStateMachine.RETRANSMIT
                elif self.eapResp:
                    rxResp, respId, respMethod = self.recieved_state()
                    self.currentState = FullEAPStateMachine.RECEIVED

            if self.currentState == FullEAPStateMachine.RETRANSMIT:
                self.retransmit_state()
                if self.retransCount > self.MAX_RETRANS:
                    self.currentState = FullEAPStateMachine.TIMEOUT_FAILURE
                else:
                    self.currentState = FullEAPStateMachine.IDLE

            if self.currentState == FullEAPStateMachine.RECEIVED:
                self.logger.debug("RECEIVED- rxResp: %s, respId: %d, respMethod: %s",
                                  rxResp, respId, respMethod)
                self.logger.debug("RECIEVED- currentId: %d, currentMethod: %s, methodState: %s",
                                  self.currentId, self.currentMethod, self.methodState)
                if rxResp and respId == self.currentId \
                        and (respMethod == MethodState.NAK
                             or respMethod == MethodState.EXPANDED_NAK) \
                        and self.methodState == MethodState.PROPOSED:
                    self.nak_state()
                    self.currentState = FullEAPStateMachine.NAK
                elif rxResp and respId == self.currentId and respMethod == self.currentMethod:
                    ignore = self.integrity_check_state()
                    self.currentState = FullEAPStateMachine.INTEGRITY_CHECK
                else:
                    self.discard_state()
                    self.currentState = FullEAPStateMachine.DISCARD

            if self.currentState == FullEAPStateMachine.DISCARD:
                self.idle_state()
                self.currentState = FullEAPStateMachine.IDLE

            if self.currentState == FullEAPStateMachine.NAK:
                decision = self.select_action_state
                self.currentState = FullEAPStateMachine.SELECT_ACTION

            if self.currentState == FullEAPStateMachine.INTEGRITY_CHECK:
                if ignore:
                    self.discard_state()
                    self.currentState = FullEAPStateMachine.DISCARD
                else:
                    self.method_response_state()
                    self.currentState = FullEAPStateMachine.METHOD_RESPONSE

            if self.currentState == FullEAPStateMachine.METHOD_RESPONSE:
                if self.methodState == MethodState.END:
                    decision = self.select_action_state()
                    self.currentState = FullEAPStateMachine.SELECT_ACTION
                else:
                    self.method_request_state()
                    self.currentState = FullEAPStateMachine.METHOD_REQUEST

            if self.currentState == FullEAPStateMachine.INITIALIZE_PASSTRHOUGH:
                if self.currentId:
                    self.aaa_request_state(respMethod)
                    self.currentState = FullEAPStateMachine.AAA_REQUEST
                else:
                    self.aaa_idle_state()
                    self.currentState = FullEAPStateMachine.AAA_IDLE

            if self.currentState == FullEAPStateMachine.AAA_IDLE:
                if self.aaaFail:
                    self.failure2_state()
                    self.currentState = FullEAPStateMachine.FAILURE2
                elif self.aaaSuccess:
                    self.success2_state()
                    self.currentState = FullEAPStateMachine.SUCCESS2
                elif self.aaaTimeout:
                    self.timeout_failure2_state()
                    self.currentState = FullEAPStateMachine.TIMEOUT_FAILURE2
                elif self.aaaEapReq:
                    self.aaa_response_state()
                    self.currentState = FullEAPStateMachine.AAA_RESPONSE
                elif self.aaaEapNoReq:
                    self.discard2_state()
                    self.currentState = FullEAPStateMachine.DISCARD2

            if self.currentState == FullEAPStateMachine.AAA_RESPONSE:
                self.send_request2_state()
                self.currentState = FullEAPStateMachine.SEND_REQUEST2

            if self.currentState == FullEAPStateMachine.SEND_REQUEST2:
                self.idle2_state()
                self.currentState = FullEAPStateMachine.IDLE2

            if self.currentState == FullEAPStateMachine.DISCARD2:
                self.idle2_state()
                self.currentState = FullEAPStateMachine.IDLE2

            if self.currentState == FullEAPStateMachine.IDLE2:
                if self.retransWhile == 0:
                    self.retransmit2_state()
                    self.currentState = FullEAPStateMachine.RETRANSMIT2
                elif self.eapResp:
                    rxResp, respId, respMethod = self.received2_state()
                    self.currentState = FullEAPStateMachine.RECEIVED2

            if self.currentState == FullEAPStateMachine.RETRANSMIT2:
                if self.retransCount > self.MAX_RETRANS:
                    self.timeout_failure2_state()
                    self.currentState = FullEAPStateMachine.TIMEOUT_FAILURE2
                else:
                    self.idle2_state()
                    self.currentState = FullEAPStateMachine.IDLE2

            if self.currentState == FullEAPStateMachine.RECEIVED2:
                if rxResp and respId == self.currentId:
                    self.aaa_request_state(respMethod)
                    self.currentState = FullEAPStateMachine.AAA_REQUEST
                else:
                    self.discard2_state()
                    self.currentState = FullEAPStateMachine.DISCARD2

            if self.currentState == FullEAPStateMachine.AAA_REQUEST:
                self.aaa_idle_state()
                self.currentState = FullEAPStateMachine.AAA_IDLE

            if self.currentState == FullEAPStateMachine.FAILURE2:
                # Do nothing.
                pass

            if self.currentState == FullEAPStateMachine.SUCCESS2:
                # RFC 4137 says do nothing from success(2), but we're adding a logoff state.
                # hopefully it will work as intended.
                # Otherwise allow transition to logoff from all states.
                if self.logoff:
                    self.logoff2_state()
                    self.currentState = FullEAPStateMachine.LOGOFF2

            if self.currentState == FullEAPStateMachine.TIMEOUT_FAILURE2:
                # Do nothing.
                pass

    def event(self, event):
        """Processes an event.
        Output is via the eap/radius queue. and again will be of type ***Message.
        Args:
            event: should have message attribute which is of the ***Message types
            (e.g. SuccessMessage, IdentityMessage,...)
        """

        self.logger.info("full state machine received event")
        # 'Lower Layer' shim
        if isinstance(event, EventMessageReceived):
            self.message_event_received(event)

        elif isinstance(event, EventTimerExpired):
            if self.timer_expired_event_received(event):
                return

        elif isinstance(event, EventPortStatusChange):
            self.port_status_event_received(event)

        self.handle_message_received()
        self.logger.info('end state: %s', self.currentState)

        if self.eapReq:
            if (hasattr(self.eapReqData, 'code') and self.eapReqData.code == Eap.REQUEST) \
                    or isinstance(self.eapReqData, (SuccessMessage, FailureMessage)):
                self.eap_output_messages.put((self.eapReqData, self.src_mac))
                self.sent_count += 1
                self.set_timer()
            else:
                self.logger.error('cant find code --- %s', self.eapReqData)
            self.eapReq = False

        if self.aaaEapResp and self.aaaEapRespData:
            if self.aaaEapRespData.code == Eap.RESPONSE:
                self.radius_output_messages.put((self.aaaEapRespData, self.src_mac,
                                                 self.aaaIdentity.identity,
                                                 self.radius_state_attribute))
                self.sent_count += 1
                self.set_timer()
            self.aaaEapResp = False
        elif self.aaaEapResp:
            self.logger.error("aaaEapResp is true. but data is false. This should never happen")

        if self.eapSuccess:
            self.logger.info('Yay authentication successful %s %s',
                             self.src_mac, self.aaaIdentity.identity)
        if self.eapFail:
            self.logger.info('oh authentication not successful %s', self.src_mac)

    def port_status_event_received(self, event):
        """Sets variables for the port status change (link up/down) being received.
        Args:
            event (EventPortStatusChange):
        """
        self.portEnabled = event.port_status

    def timer_expired_event_received(self, event):
        """Check if the event has been replied to. and set variables.
        Args:
            event (EventTimerExpired): event to process

        Returns:
            True if this event is being ignored and no further processing is required.
            Otherwise False.
        """
        self.logger.info("Expired Timer Event Received")
        if self.sent_count == event.sent_count:
            self.logger.debug("processing timer event. haven't received a reply. %s %s",
                              self.sent_count, event.sent_count)

            if self.currentState == self.AAA_IDLE:
                self.aaaTimeout = True
            if self.currentState == self.IDLE2 or self.currentState == self.IDLE:
                self.retransWhile = 0
            return False
        self.logger.debug("ignoring timer event, already received a reply.")
        return True

    def message_event_received(self, event):
        """Sets variables for the Eap message being received.
        Args:
            event (EventMessageReceived): event being processed.
        """
        self.logger.info('type: %s, message %s', type(event.message), event.message)
        self.logoff = False
        if isinstance(event.message, EapolStartMessage):
            self.eapRestart = True
        elif isinstance(event.message, EapolLogoffMessage):
            self.logoff = True
        if not isinstance(event, EventRadiusMessageReceived):
            self.eapRespData = event.message
            self.eapResp = True
        else:
            self.eapRespData = None
            self.eapResp = False
        self.eapReq = False
        self.eapNoReq = False
        self.eapSuccess = False
        self.eapFail = False
        self.aaaEapNoReq = False
        self.aaaSuccess = False
        self.aaaFail = False
        self.aaaEapKeyAvailable = False
        self.aaaEapResp = False
        self.eapLogoff = False
        if isinstance(event, EventRadiusMessageReceived):
            self.radius_state_attribute = event.state
            self.aaaEapReq = True
            self.aaaEapReqData = event.message
            self.logger.info('sm ev.msg: %s', self.aaaEapReqData)
            if isinstance(self.aaaEapReqData, SuccessMessage):
                self.logger.info("aaaSuccess")
                self.aaaSuccess = True
                self.auth_handler(self.src_mac)
            if isinstance(self.aaaEapReqData, FailureMessage):
                self.logger.info("aaaFail")
                self.aaaFail = True
        else:
            self.aaaEapReq = False

    def set_timer(self):
        """Sets a timer to trigger a retransmit if no packet received.
        """
        # These messages should not expect a reply, so set the timer.
        if self.currentState not in [self.SUCCESS, self.SUCCESS2,
                                     self.FAILURE, self.FAILURE2,
                                     self.TIMEOUT_FAILURE, self.TIMEOUT_FAILURE2]:
            timeout = self.retransWhile
            self.timer_scheduler.enter(timeout, 10,
                                       self.event,
                                       argument=[EventTimerExpired(self, self.sent_count)])
            # TODO could cancel the scheduled events when
            # they're no longer needed (i.e. response received)
