"""Test Chewie's EAP Functionality"""

import time
from base_test import BaseTest




class EapTest(BaseTest):
    """Test Chewie's EAP Functionality"""
    test_name = "EapTest"

    def setUp(self):
        """Start Radius and Chewie Servers"""
        super(EapTest, self).setUp()
        self.start_radius()
        self.start_chewie()

    def test_peap(self):
        """Attempt to connect to Chewie using PEAP on WPA_Supplicant"""
        self.start_wpa_supplicant('peap')
        time.sleep(5)
        self.check_output()

    def test_md5(self):
        """Attempt to connect to Chewie using MD5 on WPA_Supplicant"""
        self.start_wpa_supplicant('md5')
        time.sleep(5)
        self.check_output()

    def test_tls(self):
        """Attempt to connect to Chewie using TLS on WPA_Supplicant"""
        self.start_wpa_supplicant('tls')
        time.sleep(5)
        self.check_output()

    def test_ttls(self):
        """Attempt to connect to Chewie using TTLS on WPA_Supplicant"""
        self.start_wpa_supplicant('ttls')
        time.sleep(5)
        self.check_output()
