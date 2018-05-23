from eventlet.queue import Queue

class StateMachine:
    def __init__(self):
        self.state = "idle"
        self.output_messages = Queue()

    def event(self, event):
        if event.type == "packet received":
            self.output_messages.put("blah")
            self.state = "identity request sent"
