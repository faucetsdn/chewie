"""This Module provides a Bare-bones Mac Authentication Bypass State Machine provide 802.1x
MAB Support in Chewie"""

from transitions import State, Machine

from chewie.event import EventMessageReceived, EventRadiusMessageReceived
from chewie.radius import RadiusAccessAccept, RadiusAccessReject
from chewie.utils import get_logger, log_method, RadiusQueueMessage
from chewie.state_machines.abstract_state_machine import AbstractStateMachine


class MacAuthenticationBypassStateMachine(AbstractStateMachine):
    """This Class provides a Bare-bones Mac Authentication Bypass State Machine provide 802.1x
    MAB Support in Chewie"""

    # pylint: disable=too-many-instance-attributes
    # REASON: Due to class being State Machine - Requires a lot of instance attributes

    DEFAULT_SESSION_TIMEOUT = 3600  # Number of Seconds

    DISABLED = "DISABLED"
    ETH_RECEIVED = "ETH_RECEIVED"
    AAA_REQUEST = "AAA_REQUEST"
    AAA_IDLE = "AAA_IDLE"
    AAA_RECEIVED = "AAA_RECEIVED"
    AAA_SUCCESS = "AAA_SUCCESS"
    AAA_FAILURE = "AAA_FAILURE"

    INITIAL_STATE = DISABLED
    PROGRESS_STATES = [
        State(DISABLED, "mab_disabled_state"),
        State(ETH_RECEIVED, "eth_received_state"),
        State(AAA_REQUEST, "aaa_request_state"),
        State(AAA_IDLE, "aaa_idle_state"),
        State(AAA_RECEIVED, "aaa_received_state"),
    ]

    SUCCESS_STATES = [
        State(AAA_SUCCESS, "aaa_success_state"),
    ]
    FAILURE_STATES = [
        State(AAA_FAILURE, "aaa_failure_state"),
    ]
    COMPLETION_STATES = FAILURE_STATES + SUCCESS_STATES

    STATES = COMPLETION_STATES + PROGRESS_STATES

    ERROR_TRANSTIONS = [
        {
            "trigger": "process",
            "source": "*",
            "dest": DISABLED,
            "unless": ["_is_port_enabled"],
        },
        {
            "trigger": "process",
            "source": "*",
            "dest": DISABLED,
            "conditions": ["_is_mab_restart"],
        },
    ]

    CORE_TRANSITIONS = [
        {
            "trigger": "process",
            "source": DISABLED,
            "dest": ETH_RECEIVED,
            "conditions": ["_is_eth_received"],
        },
        {"trigger": "process", "source": ETH_RECEIVED, "dest": AAA_REQUEST},
        {"trigger": "process", "source": AAA_REQUEST, "dest": AAA_IDLE},
        {
            "trigger": "process",
            "source": AAA_IDLE,
            "dest": AAA_RECEIVED,
            "conditions": ["_is_aaa_received"],
        },
        # Completion States
        {
            "trigger": "process",
            "source": AAA_RECEIVED,
            "dest": AAA_FAILURE,
            "conditions": ["_is_aaa_fail"],
        },
        {
            "trigger": "process",
            "source": AAA_RECEIVED,
            "dest": AAA_SUCCESS,
            "conditions": ["_is_aaa_success"],
        },
        # On Failure - Restart Authentication
        {
            "trigger": "process",
            "source": AAA_FAILURE,
            "dest": ETH_RECEIVED,
            "conditions": ["_is_eth_received"],
        },
    ]
    TRANSITIONS = CORE_TRANSITIONS + ERROR_TRANSTIONS

    state = None

    # State Variables
    port_enabled = False
    mab_restart = False
    aaa_received = False
    aaa_fail = False
    aaa_success = False

    aaa_response_data = None
    aaa_request_data = None
    aaa_response_attributes = None

    eth_received = True
    eth_message_data = None

    radius_state_attribute = None
    # NOTE: This is not dynamic at this stage. Session timeout Attributes from radius are ignored
    session_timeout = DEFAULT_SESSION_TIMEOUT
    port_id_mac = None

    #
    # State Transition Helpers
    #
    def _is_port_enabled(self):  # pylint: disable=missing-docstring
        return self.port_enabled

    def _is_eth_received(self):  # pylint: disable=missing-docstring
        return self.eth_received

    def _is_mab_restart(self):  # pylint: disable=missing-docstring
        return self.mab_restart

    def _is_aaa_received(self):  # pylint: disable=missing-docstring
        return self.aaa_received

    def _is_aaa_fail(self):  # pylint: disable=missing-docstring
        return self.aaa_fail

    def _is_aaa_success(self):  # pylint: disable=missing-docstring
        return self.aaa_success

    #
    # State Functionality
    #
    @log_method
    def mab_disabled_state(self):  # pylint: disable=missing-docstring
        self.mab_restart = False

    @log_method
    def eth_received_state(self):  # pylint: disable=missing-docstring
        self.process_ethernet_frame()

    @log_method
    def aaa_request_state(self):  # pylint: disable=missing-docstring
        self.send_aaa_request()

    @log_method
    def aaa_idle_state(self):  # pylint: disable=missing-docstring
        pass

    @log_method
    def aaa_received_state(self):  # pylint: disable=missing-docstring
        self.process_radius_message()

    @log_method
    def aaa_success_state(self):  # pylint: disable=missing-docstring
        self.logger.info(
            "Authentication Passed: MAC is approved for MAB %s", self.src_mac
        )
        self.handle_success()

    @log_method
    def aaa_failure_state(self):  # pylint: disable=missing-docstring
        self.logger.info(
            "Authentication Failed: MAC is not approved for MAB %s", self.src_mac
        )
        self.handle_failure()

    # pylint: disable=too-many-arguments

    def __init__(
        self,
        radius_output_queue,
        src_mac,
        timer_scheduler,
        auth_handler,
        failure_handler,
        log_prefix,
    ):
        """

        Args:
            auth_handler (callable): callable that takes input of src_mac. Called on MAB-Success
            failure_handler (callable): callable that takes input of src_mac. Called on MAB-Failure.
            radius_output_queue (Queue): where to put Messages to send to AAA server
            src_mac (MacAddress): MAC address this statemachine (sm) belongs to.
            timer_scheduler (Scheduler): where to put timer events. (useful for Retransmits)
            log_prefix (String): the prefix used when outputting logs
        """
        self.radius_output_messages = radius_output_queue
        self.src_mac = src_mac
        self.timer_scheduler = timer_scheduler
        self.auth_handler = auth_handler
        self.failure_handler = failure_handler
        self.aaa_sent_count = 0
        self.set_timer = None
        self.machine = Machine(
            model=self,
            states=MacAuthenticationBypassStateMachine.STATES,
            transitions=MacAuthenticationBypassStateMachine.TRANSITIONS,
            queued=True,
            initial=MacAuthenticationBypassStateMachine.DISABLED,
        )

        self.logger = get_logger(log_prefix)

        self.reset_variables()
        self.port_enabled = True
        self.eth_received = True

    #
    # State Functionalty Helper Functions
    #

    def reset_variables(self):
        """Reset all used state-machine variables"""
        self.aaa_received = False
        self.aaa_fail = False
        self.aaa_success = False
        self.aaa_response_data = None
        self.aaa_request_data = None
        self.eth_received = False
        self.eth_message_data = None
        self.aaa_response_attributes = None

    def event(self, event):
        """Processes an event for the state machine"""
        self.logger.info(
            "Received event: %s with starting state: %s", event.__class__, self.state
        )

        self.reset_variables()

        # Process Decisions
        if isinstance(event, EventMessageReceived):
            self.event_message_received(event)
        else:
            self.logger.error(
                "MAB State Machine error. Incorrect event received. %s", event.__dict__
            )

        self.handle_event_received()
        self.logger.info("end state: %s", self.state)

    def handle_success(self):
        """Handle a AAA_Success event"""
        self.logger.info("Successful MAB Authentication. Running Auth Handler")
        self.auth_handler(
            self.src_mac,
            str(self.port_id_mac),
            self.session_timeout,
            self.aaa_response_attributes,
        )

    def handle_failure(self):
        """Handle a AAA_Failure event"""
        self.logger.info("Failed MAB Authentication. Running Failure Handler")
        self.failure_handler(self.src_mac, str(self.port_id_mac))

    def handle_event_received(self):
        """Main state machine loop"""
        last_state = None
        while self.state != last_state:
            last_state = self.state
            self.process()  # pylint: disable=no-member # pytype: disable=attribute-error

    def event_message_received(self, event):
        """Handle a message received event"""
        if event.port_id:
            self.port_id_mac = event.port_id

        if isinstance(event, EventRadiusMessageReceived):
            self.aaa_received = True
            self.aaa_response_data = event.message
            self.aaa_response_attributes = event.attributes

            if isinstance(self.aaa_response_data, RadiusAccessAccept):
                self.aaa_success = True
            elif isinstance(self.aaa_response_data, RadiusAccessReject):
                self.aaa_fail = True

        else:
            self.eth_received = True
            self.eth_message_data = event.message

    def process_ethernet_frame(self):
        """Perform checks on ethernet frames"""

    def process_radius_message(self):
        """Perform checks on Radius Packets before they're passed to the State Machine"""
        if not isinstance(
            self.aaa_response_data, RadiusAccessAccept
        ) and not isinstance(self.aaa_response_data, RadiusAccessReject):
            raise Exception(
                "Unexpected Packet Type in MAB state Machine: %s"
                % self.aaa_response_data.__dict__
            )

    def send_aaa_request(self):
        """Perform sending a AAA Request"""
        port_id = self.port_id_mac
        ethernet_packet = self.eth_message_data
        src_mac = ethernet_packet.src_mac

        # Build the RADIUS Packet and send
        self.radius_output_messages.put_nowait(
            RadiusQueueMessage(
                src_mac, src_mac, src_mac, self.radius_state_attribute, port_id
            )
        )

        self.aaa_sent_count += 1
