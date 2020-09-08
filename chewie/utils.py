"""Utility Functions"""
import logging
import random
from collections import namedtuple  # pytype: disable=pyi-error


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


def get_random_id():  # pylint: disable=missing-docstring
    """pick a random 8 bit EAPOL ID - which cannot be 0."""
    return random.randint(1, 2**8 - 1)


class MessageParseError(Exception):
    """Error for when parsing cannot be successfully completed."""
    pass


class EapQueueMessage(namedtuple('EapQueueMessage',
                                 'message src_mac port_mac')):
    pass


class RadiusQueueMessage(namedtuple('RadiusQueueMessage',
                                    'message src_mac identity state port_mac')):
    pass
