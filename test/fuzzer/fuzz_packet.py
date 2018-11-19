#!/usr/bin/env python3

"""Run AFL repeatedly with externally supplied generated packet from STDIN."""

import struct
import sys

import afl

#from chewie.radius import InvalidResponseAuthenticatorError, InvalidMessageAuthenticatorError
from chewie.mac_address import MacAddress
from chewie.message_parser import MessageParser

ROUNDS = 1


def main(eap):
    """Run AFL repeatedly with externally supplied generated packet from STDIN."""

    while afl.loop(ROUNDS):
    # afl.start()
    # if True:
        # receive input from afl
        rcv = sys.stdin.read()
        data = None
        try:
            data = bytearray.fromhex(rcv)  # pytype: disable=missing-parameter
        except (ValueError, TypeError):
            return
        if eap:
            test_eap_parse(data)
        # else:
        #     test_radius_parse(data)
#
#
# def test_ethernet_parse(data):
#     try:
#         MessageParser.ethernet_parse(data)
#     except (ValueError, struct.error) as e:
#         if e.message.startswith("unpack requires a buffer of 14 bytes"):
#             pass
#         elif e.message.startswith("Ethernet packet with bad ethertype received:"):
#             pass
#         else:
#             raise


def test_eap_parse(data):
    try:
        MessageParser.eap_parse(data, MacAddress.from_string("00:00:00:12:34:56"))
    except (KeyError, UnicodeDecodeError, ValueError, struct.error) as e:
        # Ignore exceptions the parser intentionally throws, and are caught by the caller.
        pass


# def test_radius_parse(data):
#     try:
#         MessageParser.radius_parse(data, "SECRET", request_authenticator_callback=lambda x: None)
#     # except (InvalidResponseAuthenticatorError, InvalidMessageAuthenticatorError) as e:
#     except (ValueError) as e:
#         if e.message.startswith("Unable to parse radius code:"):
#             pass
#         else:
#             raise


if __name__ == "__main__":
    parser = sys.argv[1]
    eap = False
    if parser == 'eap':
        eap = True
    main(eap)
