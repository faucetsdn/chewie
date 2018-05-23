class Event(object):
    TIMER_EXPIRED = 1
    MESSAGE_RECEIVED = 2
    SHUTDOWN = 3

class EventTimerExpired(Event):
    def __init__(self):
        # will work but please do this properly
        self.type = self.TIMER_EXPIRED

class EventMessageReceived(Event):
    def __init__(self, message):
        # will work but please do this properly
        self.type = self.MESSAGE_RECEIVED
        self.message = message

class EventShutdown(Event):
    def __init__(self):
        # will work but please do this properly
        self.type = self.SHUTDOWN
