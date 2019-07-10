"""Test Chewie's MAB Functionality"""

import time
from base_test import BaseTest
import unittest

CONFIG_FILENAME = "/tmp/wpasupplicant/wired-tmp.conf"
supplicant_config_template = """
ctrl_interface=/tmp/wpa_supplicant
ctrl_interface_group=0
ap_scan=0

network={{
 key_mgmt=IEEE8021X
 eap=MD5
 identity="{0}"
 password="{1}"
 eapol_flags=0
}}"""


# TODO : should really not be so dependent on the radius users file
# TODO : should also test for mab
class RadiusAttributeOnAuthentication(BaseTest):
    """Test Chewie's MAB Functionality"""
    test_name = "RadiusAttributeOnAuthentication"

    def create_supplicant_config(self, identity, password):
        with open(CONFIG_FILENAME, "w+") as tmp_wpa_config:
            tmp_wpa_config.write(supplicant_config_template.format(identity, password))

    def setUp(self):
        """Start Radius and Chewie Servers"""
        super(RadiusAttributeOnAuthentication, self).setUp()
        self.start_radius()
        self.start_chewie()

    def test_smoke_vlan_id(self):
        """Perform MAB using dhclient"""
        self.create_supplicant_config("vlan_id", "microphone")
        self.start_wpa_supplicant('tmp')
        time.sleep(5)
        requirements = ['kwargs : vlan_name : VLAN_100']

        self.check_output(chewie_requirements=requirements)

    def test_smoke_filter_id(self):
        """Perform MAB using dhclient"""
        self.create_supplicant_config("filter_id", "microphone")
        self.start_wpa_supplicant('tmp')
        time.sleep(5)
        requirements = ['kwargs : filter_id : ACL_1']
        self.check_output(chewie_requirements=requirements)

    @unittest.skip("Skipping as not implemented yet.")
    def test_smoke_nas_filter_rule(self):
        """Perform MAB using dhclient"""
        self.create_supplicant_config("filter_rule", "microphone")
        self.start_wpa_supplicant('tmp')
        time.sleep(5)
        requirements = ['kwargs : NAS-Filter-Rule : deny in tcp from any to any']
        self.check_output(chewie_requirements=requirements)
