"""Various Events used by Chewie"""

# pylint: disable=too-few-public-methods


class Event:
    """Base event class"""
    TIMER_EXPIRED = 1
    MESSAGE_RECEIVED = 2
    SHUTDOWN = 3
    PORT_ENABLED = 4
    PORT_DISABLED = 5


class EventTimerExpired(Event):
    """Used when a timer has expired."""
    def __init__(self, state_machine=None, sent_count=None):
        """
        Args:
            state_machine: state machine that triggered the event
            sent_count: number of packets sent at time of event creation.
        """
        # will work but please do this properly
        self.type = self.TIMER_EXPIRED
        self.state_machine = state_machine
        self.sent_count = sent_count


class EventSessionTimeout(Event):
    """User's session should be terminated."""
    def __init__(self, state_machine=None):
        """
        Args:
            state_machine: state machine that triggered the event
        """
        self.type = self.TIMER_EXPIRED
        self.state_machine = state_machine


class EventMessageReceived(Event):
    """Message (EAP) Received. Radius Message event is a child"""
    def __init__(self, message, port_id):
        """
        Args:
            message:
            port_id: id of switch port where message was received.
        """
        # will work but please do this properly
        self.type = self.MESSAGE_RECEIVED
        self.message = message
        self.port_id = port_id

    def __eq__(self, other):
        return self.type == other.type and \
            self.message == other.message and \
            self.port_id == other.port_id

    def __repr__(self):
        return "%s(\"%s\", \"%s\")" % (self.__class__.__name__, self.message, self.port_id)


class EventPortStatusChange(Event):
    """Port status has changed (up/down)"""

    def __init__(self, port_status):
        """
        Args:
            port_status (bool): True if port is enabled, False otherwise.
        """
        self.port_status = port_status
        if port_status:
            self.type = self.PORT_ENABLED
        else:
            self.type = self.PORT_DISABLED


class EventRadiusMessageReceived(EventMessageReceived):
    """Radius Message Received."""

    def __init__(self, message, state, attributes=None):
        """
        Args:
            message:
            state: the RADIUS state attribute
        """
        super().__init__(message, None)
        self.state = state
        self.attributes = attributes


class EventShutdown(Event):
    """Shutdown has been signaled (is this even used?)"""
    def __init__(self):
        # will work but please do this properly
        self.type = self.SHUTDOWN
