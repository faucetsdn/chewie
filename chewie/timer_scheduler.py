"""Homebrew Event scheduler, as sched.scheduler was not working outside of unittests"""
import heapq
import time

import eventlet


class TimerScheduler:
    """wraps a heapbased queue with a similar api to asyncio.loop"""

    def __init__(self, logger, sleep=None):
        self.logger = logger
        self.timer_heap = []

        self.sleep = eventlet.sleep
        if sleep:
            self.sleep = sleep

    def call_later(self, timeout, func, *args):
        """

        Args:
            timeout: number of seconds to delay executing func
            func: function to execute
            *args: arguments for func

        Returns:
            tuple (expiry_time, dict) - can be used for cancelling the job
        """
        if not args:
            args = []
        job = (time.time() + timeout, {'func': func, 'args': args, 'alive': True})
        heapq.heappush(self.timer_heap, job)
        return job

    def run(self):
        """Main loop. should run forever"""
        try:
            while True:
                if len(self.timer_heap):
                    if self.timer_heap[0][0] < time.time():
                        _, job = heapq.heappop(self.timer_heap)
                        if job['alive']:
                            self.logger.info('running job %s', job['func'].__name__)
                            job['func'](*job['args'])
                        else:
                            self.logger.info('job %s has been cancelled', job['func'].__name__)
                    else:
                        self.sleep(1)
                else:
                    self.sleep(1)
        except Exception as e:
            self.logger.exception(e)
