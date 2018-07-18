class Event(object):
    TIMER_EXPIRED = 1
    MESSAGE_RECEIVED = 2
    SHUTDOWN = 3


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


class EventRadiusMessageReceived(EventMessageReceived):

    def __init__(self, message, state):
        super().__init__(message)
        self.state = state


class EventShutdown(Event):
    def __init__(self):
        # will work but please do this properly
        self.type = self.SHUTDOWN
