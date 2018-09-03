from chewie.chewie import Chewie
import chewie.utils as utils


credentials = {
    "user@example.com": "microphone"
}


def auth_handler(address, group_address):
    print("Authed address %s on port %s" % (str(address), str(group_address)))


logger = utils.get_logger("CHEWIE")
logger.info('starting chewieeeee.')

chewie = Chewie("eth1", credentials, logger, auth_handler, radius_server_ip="172.24.0.113")
chewie.run()
