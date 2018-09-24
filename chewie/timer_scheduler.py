import heapq
import time

import eventlet


class TimerScheduler:

    def __init__(self, logger, sleep=None):
        self.logger = logger
        self.timer_heap = []

        self.sleep = eventlet.sleep
        if sleep:
            self.sleep = sleep

    def call_later(self, timeout, func, *args):
        if not args:
            args = []
        job = (time.time() + timeout, {'func': func, 'args': args, 'alive': True})
        heapq.heappush(self.timer_heap, job)
        return job

    def run(self):
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
                        self.logger.info('too early for job - sleeping')
                        self.sleep(1)
                else:
                    self.logger.info('job Queue empty - sleeping')
                    self.sleep(1)
        except Exception as e:
            self.logger.exception(e)
