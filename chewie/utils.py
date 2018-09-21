"""Utility Functions"""
import heapq
import logging
import time


def get_logger(logname):
    """Create and return a logger object."""
    logger = logging.getLogger(logname)
    return logger


def log_method(method):
    def wrapped(self, *args, **kwargs):
        self.logger.info('Entering %s' % method.__name__)
        return method(self, *args, **kwargs)
    return wrapped


def push_job(heap, delay, func, args=None):
    if not args:
        args = []
    job = (time.time() + delay, {'func': func, 'args': args, 'alive': True})
    heapq.heappush(heap, job)
    return job
