"""Utility Functions"""
import logging


def get_logger(logname):
    """Create and return a logger object."""
    logger = logging.getLogger(logname)
    return logger


def log_method(method):
    def wrapped(self, *args, **kwargs):
        self.logger.info('Entering %s' % method.__name__)
        return method(self, *args, **kwargs)
    return wrapped
