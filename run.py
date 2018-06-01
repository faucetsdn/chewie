import socket
import struct
from select import select
from fcntl import ioctl
from netils import build_byte_string

from chewie.chewie import Chewie

class Logger:
    def info(self, message):
        print("INFO: %s" % message)

    def warning(self, message):
        print("WARNING: %s" % message)

def auth_handler(address):
    print("Authed address %s" % str(address))

credentials = {
    "user@example.com": "microphone"
}
chewie = Chewie("eth0", credentials, Logger(), auth_handler)
chewie.run()
