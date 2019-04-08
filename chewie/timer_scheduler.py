"""Homebrew Event scheduler, as sched.scheduler was not working outside of unittests"""
import heapq
import time

import eventlet


class TimerJob:
    """Represents a job for TimerScheduler, same api as asyncio.TimerHandle"""

    expiry_time = 0
    is_cancelled = False
    func = None
    args = None

    def __init__(self, expiry_time, func, args):
        self.expiry_time = expiry_time
        self.func = func
        self.args = args

    def cancel(self):
        """Cancel the callback."""
        self.is_cancelled = True

    def cancelled(self):
        """
        Returns:
            True if callback was cancelled
        """
        return self.is_cancelled

    def when(self):
        """
        Returns:
            scheduled callback time as float seconds
        """
        return self.expiry_time


class TimerScheduler:
    """wraps a heapbased queue with a similar api to asyncio.loop"""

    def __init__(self, logger, sleep=None):
        self.logger = logger
        self.timer_heap = []

        self.sleep = eventlet.sleep
        if sleep:
            self.sleep = sleep

    def call_later(self, timeout, func, *args):
        """Scheduler callback.

        Args:
            timeout: number of seconds to delay executing func
            func: function to execute
            *args: arguments for func

        Returns:
            tuple (expiry_time, dict) - can be used for cancelling the job
        """
        if not args:
            args = []
        self.logger.debug("submitted job %s expire in %d, args: %s", func.__name__, timeout, args)
        expiry_time = time.time() + timeout

        job = TimerJob(expiry_time, func, args)
        heapq.heappush(self.timer_heap, (expiry_time, job))
        return job

    def run(self):
        """Main loop. should run forever"""
        while True:
            try:
                if self.timer_heap:
                    if self.timer_heap[0][0] < time.time():
                        _, job = heapq.heappop(self.timer_heap)
                        if not job.cancelled():
                            self.logger.info('running job %s %s', job.func.__name__, job.args)
                            job.func(*job.args)
                        else:
                            self.logger.debug('job %s has been cancelled', job.func.__name__)
                    else:
                        self.sleep(1)
                else:
                    self.sleep(1)
            except Exception as e:
                self.logger.exception(e)
        self.logger.warning('timer_scheduler finished quuee')
