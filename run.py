import logging
import sys

from chewie.chewie import Chewie


def get_logger(name, log_level=logging.DEBUG):
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(log_level)
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(log_level)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)
    return logger


def auth_handler(address, group_address):
    print("Authed address %s on port %s" % (str(address), str(group_address)))


def failure_handler(address, group_address):
    print("failure of address %s on port %s" % (str(address), str(group_address)))


def logoff_handler(address, group_address):
    print("logoff of address %s on port %s" % (str(address), str(group_address)))


logger = get_logger("CHEWIE")
logger.info('starting chewieeeee.')

chewie = Chewie("eth1", logger, auth_handler, failure_handler, logoff_handler, radius_server_ip="172.24.0.113", radius_server_secret="SECRET")
chewie.run()
