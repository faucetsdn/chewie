"""Mock TimerScheduler
"""


class FakeTimerJob:
    """Behaves like TimerJob"""
    def __init__(self, function, args, timeout):
        self.function = function
        self.args = args
        self.timeout = timeout
        self.is_cancelled = False

    def cancel(self):
        """Clones TimerJob.cancel()"""
        self.is_cancelled = True

    def cancelled(self):
        """Clones TimerJob.cancelled()"""
        return self.is_cancelled

    def run(self):
        """Runs job"""
        if not self.is_cancelled:
            self.function(*self.args)


class FakeTimerScheduler:
    """Behaves like TimerScheduler"""
    def __init__(self):
        self.jobs = []

    def call_later(self, timeout, func, *args):
        """Clones TimerScheduler.call_later()"""
        if not args:
            args = []

        job = FakeTimerJob(func, args, timeout)

        self.jobs.append(job)

        return job

    def run_jobs(self, num_jobs=None):
        """Runs jobs in order of timeout"""
        if not num_jobs:
            while self.jobs:
                self.jobs.sort(key=lambda x: x.timeout)
                job = self.jobs.pop(0)
                job.run()
                print("ddddddddd")
        else:
            for _ in range(num_jobs):
                if not self.jobs:
                    break
                self.jobs.sort(key=lambda x: x.timeout)
                job = self.jobs.pop(0)
                job.run()
                print("eeeeeeeeez")

    def run(self):
        """Clones TimerScheduler.run()"""
        pass
