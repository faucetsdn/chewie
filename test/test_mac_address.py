
# pylint: disable=missing-docstring

import unittest

from chewie.mac_address import MacAddress


class MacAddressTestCase(unittest.TestCase):
    """Test MacAddress class."""

    def test_from_string_valid(self):
        """Test valid mac address input."""
        examples = {
            '01:02:03:04:05:06': b'\x01\x02\x03\x04\x05\x06',
            '01:02:03:04:05:7': b'\x01\x02\x03\x04\x05\x07',
            '0a:0b:0c:0d:0e:0f': b'\x0a\x0b\x0c\x0d\x0e\x0f',
            '0a:0b:0c:0d:0e:f': b'\x0a\x0b\x0c\x0d\x0e\x0f',
            '1:2:3:4:5:6': b'\x01\x02\x03\x04\x05\x06',
            'a:b:c:D:E:F': b'\x0a\x0b\x0c\x0d\x0e\x0f'
        }
        for key, data in examples.items():
            addr = MacAddress.from_string(key)
            self.assertEqual(addr.address, data)

    def test_from_string_invalid(self):
        """Test invalid mac address input."""
        examples = [
            '01:02:03:04:05',
            '01::03:04:05:06',
            '01:02:03:04:05: 6',
            '01:02:03:04:05:6\n',
            ' 1:02:03:04:05:06',
            '01:02:03:04:05:06:07',
            '0:0:0:0:0:007',
            '0a:0b:0c:0d:0e:0g',
            '0a:0b:0c:0d:0e:fff',
            '01-02-03-04-05-06',
            '0001:0002:0003',
            '000001:000002'
        ]
        for key in examples:
            with self.assertRaisesRegex(ValueError, r'%s.+MAC address' % key):
                MacAddress.from_string(key)

    def test_hash_and_equals(self):
        """Test mac address __hash__ and __eq__."""
        addr1 = MacAddress.from_string('01:02:03:04:05:06')
        addr2 = MacAddress(b'\x01\x02\x03\x04\x05\x06')
        self.assertEqual(addr1, addr2)
        self.assertEqual(hash(addr1), hash(addr2))

    def test_repr(self):
        """Test mac address __repr__."""
        value = repr(MacAddress.from_string('01:02:03:04:05:06'))
        self.assertEqual(value, 'MacAddress.from_string("01:02:03:04:05:06")')
