#!/usr/bin/env python3

"""Run AFL repeatedly with externally supplied generated packet from STDIN."""

import logging
import struct
import sys

import afl

#from chewie.radius import InvalidResponseAuthenticatorError, InvalidMessageAuthenticatorError
from chewie.message_parser import MessageParser

ROUNDS = 1
logging.disable(logging.CRITICAL)


def main(eap):
    """Run AFL repeatedly with externally supplied generated packet from STDIN."""

    while afl.loop(ROUNDS):
        # receive input from afl
        rcv = sys.stdin.read()
        data = None
        try:
            data = bytearray.fromhex(rcv) # pytype: disable=missing-parameter
        except (ValueError, TypeError):
            continue
        if eap:
            test_ethernet_parse(data)
        else:
            test_radius_parse(data)


def test_ethernet_parse(data):
    try:
        MessageParser.ethernet_parse(data)
    except (ValueError, struct.error) as e:
        if e.message.startswith("unpack requires a buffer of 14 bytes"):
            pass
        elif e.message.startswith("Ethernet packet with bad ethertype received:"):
            pass
        else:
            raise


def test_radius_parse(data):
    try:
        MessageParser.radius_parse(data, "SECRET", request_authenticator_callback=lambda x: None)
    # except (InvalidResponseAuthenticatorError, InvalidMessageAuthenticatorError) as e:
    except (ValueError) as e:
        if e.message.startswith("Unable to parse radius code:"):
            pass
        else:
            raise


if __name__ == "__main__":
    parser = sys.argv[1]
    eap = False
    if parser == 'eap':
        eap = True
    main(eap)