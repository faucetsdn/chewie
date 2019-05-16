import logging
import sys
import argparse

from chewie.chewie import Chewie

# Change to setup the logger
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


def auth_handler(address, group_address, *args, **kwargs):
    logger = get_logger("CHEWIE")
    logger.info("Authentication successful for address {} on port {}".format(str(address), str(group_address)))
    logger.info("Arguments passed from Chewie to Faucet: \n*args:{}\n**kwargs{}".format(str(
        args), str(kwargs)))

def failure_handler(address, group_address):
    print("failure of address %s on port %s" % (str(address), str(group_address)))


def logoff_handler(address, group_address):
    print("logoff of address %s on port %s" % (str(address), str(group_address)))


def main():
    parser = argparse.ArgumentParser(description='Run Chewie 802.1x Authenticator independently of '
                                                 'Faucet SDN Controller')

    parser.add_argument('-i', '--interface', dest='interface',
                        help='Set the interface for Chewie to listen on - Default: eth0',
                        default="eth0")
    parser.add_argument('-ri', '--radius_ip', dest='radius_ip',
                        help='Set the IP Address for the RADIUS Server that Chewie will forward requests to '
                             '- DEFAULT: 127.0.0.1', default='127.0.0.1')
    parser.add_argument('-rs', '--radius_secret', dest='radius_secret',
                        help='Set the Secret used for connecting to the RADIUS Server - Default: SECRET',
                        default='SECRET')
    args = parser.parse_args()

    logger = get_logger("CHEWIE")
    logger.info('starting chewieeeee.')

    chewie = Chewie(args.interface, logger, auth_handler, failure_handler, logoff_handler,
                    radius_server_ip=args.radius_ip, radius_server_secret=args.radius_secret)
    chewie.run()


if __name__ == '__main__':
  main()