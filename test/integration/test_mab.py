"""Test Chewie's MAB Functionality"""

import time
from base_test import BaseTest


class MabTest(BaseTest):
    """Test Chewie's MAB Functionality"""
    test_name = "MabTest"

    def setUp(self):
        """Start Radius and Chewie Servers"""
        super().setUp()
        self.start_radius()
        self.start_chewie()

    def test_smoke_mab(self):
        """Perform MAB using dhclient"""
        self.start_dhclient()
        for r in range(3):
            time.sleep(5)
            try:
                self.check_output()
            except AssertionError as err:
                continue
            return
        self.fail(err)
