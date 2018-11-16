import os
import struct

from chewie.message_parser import MessageParser, MessagePacker
from chewie.radius_attributes import EAPMessage, State, CalledStationId, NASIdentifier, NASPortType

def port_id_to_int(port_id):
    """"Convert a port_id str '00:00:00:00:aa:01 to integer'"""
    dp, port = str(port_id).split(':')[4:]
    return int.from_bytes(struct.pack('!HH', int(dp, 16), int(port, 16)), 'big')  # pytype: disable=attribute-error

class RadiusLifecycle:
    def __init__(self, radius_secret, server_id, logger):
        self.radius_secret = radius_secret
        self.server_id = server_id
        self.logger = logger

        self.next_radius_id = 0
        self.extra_radius_request_attributes = self.prepare_extra_radius_attributes()

        self.packet_id_to_mac = {}  # radius_packet_id: mac
        self.packet_id_to_request_authenticator = {}

    def process_outbound(self, radius_output_bits):
        eap_message, src_mac, username, state, port_id = radius_output_bits
        self.logger.info("got eap to send to radius.. mac: %s %s, username: %s",
                         type(src_mac), src_mac, username)
        state_dict = None
        if state:
            state_dict = state.__dict__
        self.logger.info("Sending to RADIUS eap message %s with state %s",
                         eap_message.__dict__, state_dict)
        radius_packet_id = self.get_next_radius_packet_id()
        self.packet_id_to_mac[radius_packet_id] = {'src_mac': src_mac, 'port_id': port_id}
        # message is eap. needs to be wrapped into a radius packet.
        request_authenticator = os.urandom(16)
        self.packet_id_to_request_authenticator[radius_packet_id] = request_authenticator
        return MessagePacker.radius_pack(eap_message, src_mac, username,
                                         radius_packet_id, request_authenticator, state,
                                         self.radius_secret,
                                         port_id_to_int(port_id),
                                         self.extra_radius_request_attributes)

    def get_next_radius_packet_id(self):
        """Calulate the next RADIUS Packet ID
        Returns:
            int
        """
        radius_id = self.next_radius_id
        self.next_radius_id = (self.next_radius_id + 1) % 256

        return radius_id

    def prepare_extra_radius_attributes(self):
        """Create RADIUS Attirbutes to be sent with every RADIUS request"""
        attr_list = [CalledStationId.create(self.server_id),
                     NASPortType.create(15),
                     NASIdentifier.create(self.server_id)]
        return attr_list
