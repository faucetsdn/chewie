import unittest
from netils import build_byte_string
from chewie.ethernet_packet import EthernetPacket
from chewie.mac_address import MacAddress

class EthernetPacketTestCase(unittest.TestCase):
    def test_ethernet_packet_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e0100000501010005010000")
        message = EthernetPacket.parse(packed_message)
        self.assertEqual(message.src_mac, MacAddress.from_string("00:19:06:ea:b8:8c"))
        self.assertEqual(message.dst_mac, MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(message.ethertype, 0x888e)
        self.assertEqual(message.data, build_byte_string("0100000501010005010000"))

    def test_ethernet_packet_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001906eab88c888e0100000501010005010000")
        message = EthernetPacket(dst_mac=MacAddress.from_string("01:80:c2:00:00:03"), src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"), ethertype=0x888e, data=build_byte_string("0100000501010005010000"))
        packed_message = message.pack()
        self.assertEqual(expected_packed_message, packed_message)
