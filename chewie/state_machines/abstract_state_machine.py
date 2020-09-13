"""This Module provides the Abstract Design Requirements for a State Machine in Chewie"""
from transitions.extensions import GraphMachine


class AbstractStateMachine:
    """This Class provides the Abstract Design Requirements for a State Machine in Chewie"""

    PROGRESS_STATES = []

    SUCCESS_STATES = []
    FAILURE_STATES = []
    COMPLETION_STATES = FAILURE_STATES + SUCCESS_STATES
    INITIAL_STATE = None
    STATES = COMPLETION_STATES + PROGRESS_STATES

    ERROR_TRANSTIONS = []

    CORE_TRANSITIONS = []
    TRANSITIONS = CORE_TRANSITIONS + ERROR_TRANSTIONS
    port_enabled = None
    state = None

    def is_in_progress(self):
        """
        Returns true if the state machine is currently in progress
        """
        return self.port_enabled and self.state not in self.COMPLETION_STATES

    def is_success(self):
        """
        Returns true if the state machine currently in a successful completion state and enabled
        """
        return self.port_enabled and self.state in self.SUCCESS_STATES

    @classmethod
    def build_state_graph(cls, filename):
        "Build a graphc representation of the state machine and store in 'filename'.png"
        model = type('model', (object,), {})()
        GraphMachine(model=model, states=cls.STATES,
                     title=cls.__name__,
                     transitions=cls.CORE_TRANSITIONS,
                     queued=True,
                     initial=cls.INITIAL_STATE)
        # pylint: disable=no-member
        # pytype: disable=attribute-error
        model.get_graph().draw(filename, prog='dot')
