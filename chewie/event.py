class Event(object):
    TIMER_EXPIRED = 1
    MESSAGE_RECEIVED = 2
    SHUTDOWN = 3
    PORT_ENABLED = 4
    PORT_DISABLED = 5


class EventTimerExpired(Event):
    def __init__(self, state_machine=None, sent_count=None):
        # will work but please do this properly
        self.type = self.TIMER_EXPIRED
        self.state_machine = state_machine
        self.sent_count = sent_count


class EventMessageReceived(Event):
    def __init__(self, message):
        # will work but please do this properly
        self.type = self.MESSAGE_RECEIVED
        self.message = message


class EventPortStatusChange(Event):

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

    def __init__(self, message, state):
        super().__init__(message)
        self.state = state


class EventShutdown(Event):
    def __init__(self):
        # will work but please do this properly
        self.type = self.SHUTDOWN
