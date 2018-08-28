class Timer:
    def __init__(self, count):
        self.count = count
        self.tick = None

    def running(self):
        return bool(self.tick)

    def expired(self, tick):
        return self.running() and tick > self.tick + self.count

    def reset(self, tick):
        self.tick = tick

    def stop(self):
        self.tick = None
