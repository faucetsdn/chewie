"""Handle the RADIUS socket
"""
from eventlet.green import socket

class RadiusSocket:
    """Handle the RADIUS socket"""
    def __init__(self, listen_ip, listen_port, server_ip, server_port):
        self.socket = None
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.server_ip = server_ip
        self.server_port = server_port

    def setup(self):
        """Setup RADIUS Socket"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # pylint: disable=no-member
        self.socket.bind((self.listen_ip, self.listen_port))

    def send(self, data):
        """Sends on the radius socket
            data (bytes): what to send"""
        self.socket.sendto(data, (self.server_ip, self.server_port))

    def receive(self):
        """Receives from the radius socket"""
        return self.socket.recv(4096)
