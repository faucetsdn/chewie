"""Utility Functions"""
import logging


def get_logger(logname):
    """Create and return a logger object."""
    logger = logging.getLogger(logname)
    return logger


def log_method(method):
    """Generate method for logging"""
    def wrapped(self, *args, **kwargs):
        """Method that gets called for logging"""
        self.logger.info('Entering %s' % method.__name__)
        return method(self, *args, **kwargs)
    return wrapped


class MessageParseError(Exception):
    """Error for when parsing cannot be successfully completed."""

    def __init__(self, message=None, original_error=None):
        """

        Args:
            message (str):
            original_error (Exception): error that MessageParser is silencing.
        """
        super().__init__(message)
        self.message = message
        self.original_error = original_error
