"""This module is used as a base for other integration tests"""

# To extract the logs from the Docker instance, override /tmp/logs


import inspect
import os
import shutil
import signal
import subprocess
import unittest
import tempfile
from collections import namedtuple
import logging
import sys

from chewie.chewie import Chewie


def get_logger(name, file=sys.stdout, log_level=logging.DEBUG):
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(log_level)
        handler = logging.StreamHandler(file)
        handler.setLevel(log_level)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


VethLink = namedtuple('VethLink', 'name ip mac')

CHEWIE_SUPPLICANT = VethLink('chewie_supp', '192.168.20.1', '8e:00:00:00:01:01')
# TODO - Add namespaces
CHEWIE_RADIUS = VethLink('chewie_radius', '192.168.21.1', '8e:00:00:00:02:01')
SUPPLICANT = VethLink('supplicant', '192.168.20.2', '8e:00:00:00:01:02')
RADIUS = VethLink('radius', '127.0.0.1', '8e:00:00:00:02:02')

# NOTE: DO NOT CHANGE THESE VALUES UNLESS CHANGES ARE MADE TO THE FREERADIUS CONFIGURATION FILES
RADIUS_IP = RADIUS.ip
RADIUS_PORT = "1812"
RADIUS_SECRET = "SECRET"

IP_LINK_PAIRS = {
    CHEWIE_SUPPLICANT: SUPPLICANT,
    CHEWIE_RADIUS: RADIUS,
}


LOG_DIR = '/tmp/logs/'
os.makedirs(LOG_DIR, exist_ok=True)

HANDLER_COUNTS = {}

CHEWIE_ROOT = os.environ.get('CHEWIE_ROOT', None)

if not CHEWIE_ROOT:
    CHEWIE_ROOT = '/chewie-src/'

CHEWIE_CONF_DIR = CHEWIE_ROOT + '/etc/'

def auth_handler(address, group_address, *args, **kwargs):  # pylint: disable=missing-docstring
    logger = logging.getLogger('CHEWIE')
    logger.info("Authentication successful for address {} on port {}".format(
        str(address), str(group_address)))
    logger.info("Arguments passed from Chewie to Faucet: \n*args:{}".format(str(args)))

    if kwargs:
        for key, value in kwargs.items():
            logger.info("kwargs : " + str(key) + " : " + str(value))

    HANDLER_COUNTS['auth_handler'] += 1


def failure_handler(address, group_address):  # pylint: disable=missing-docstring
    logger = logging.getLogger('CHEWIE')
    logger.info("Authentication failed for address {} on port {}".format(
        str(address), str(group_address)))

    HANDLER_COUNTS['failure_handler'] += 1


def logoff_handler(address, group_address):  # pylint: disable=missing-docstring
    logger = logging.getLogger('CHEWIE')
    logger.info("Logoff Successful for address {} on port {}".format(
        str(address), str(group_address)))

    HANDLER_COUNTS['logoff_handler'] += 1


class BaseTest(unittest.TestCase):
    """
    This class can be used to hold common functionality of integration tests for Chewie
    Inherit from this class to have an environment set up for the tests to run in.
    """
    active_processes = []
    freeradius_log = None
    wpa_supplicant_log = None
    current_log_dir = None

    test_name = "BaseTest"

    @classmethod
    def setUpClass(cls):
        cls.prepare_freeradius()
        cls.prepare_wpa_supplicant()

    def setUp(self):
        """Setup environment for tests to start processes"""

        self.active_processes = []
        self.freeradius_log = None
        self.wpa_supplicant_log = None

        HANDLER_COUNTS = {
            'auth_handler': 0,
            'logoff_handler': 0,
            'failure_handler': 0
        }

        for link1, link2 in IP_LINK_PAIRS.items():
            self.run_command_and_wait(
                "ip link add {} type veth peer name {}".format(link1.name, link2.name))
            for link in [link1, link2]:
                self.run_command_and_wait(
                    "ip link set dev {} address {}".format(link.name, link.mac))
                self.run_command_and_wait("ip link set {} up".format(link.name))

        self.open_logs()

    def tearDown(self):
        """Close Logs and Kill Opened Processes"""
        self.close_logs()

        if self.chewie_pid != 0:
            os.kill(self.chewie_pid, signal.SIGKILL)

        for proc in self.active_processes:
            os.kill(proc.pid, signal.SIGKILL)
            proc.wait()

        for link1, _ in IP_LINK_PAIRS.items():
            self.run_command_and_wait("ip link del {}".format(link1.name))

    def open_logs(self):
        """Open Logs for Processes"""
        self.current_log_dir = tempfile.mkdtemp(prefix='chewie-' + self.test_name + '-',
                                                dir='/tmp/logs') + "/"
        print('Logging test results in {}'.format(self.current_log_dir))
        print(os.path.join(self.current_log_dir + "wpa_supplicant.log"))
        self.freeradius_log = open(os.path.join(self.current_log_dir, "freeradius.log"), "w+")
        self.wpa_supplicant_log = open(os.path.join(self.current_log_dir + "wpa_supplicant.log"),
                                       "w+")

    def close_logs(self):
        """Close Process Logs"""
        self.freeradius_log.close()
        self.wpa_supplicant_log.close()

    def run_command_and_wait(self, command, output_file=None):  # pylint: disable=no-self-use
        """Run a command and wait for the process to complete"""
        if output_file:
            child = subprocess.Popen(command.split(), stdout=output_file)
        else:
            child = subprocess.Popen(command.split())

        result = child.wait()
        if result != 0:
            raise Exception(
                "Command returned with a non-zero exit code. Code: {}, Command: {}".format(
                    str(result), command))

    def run_command_and_detach(self, command, output_file=None):
        """Run a command and return the process"""
        if output_file:
            child = subprocess.Popen(command.split(), stdout=output_file)
        else:
            child = subprocess.Popen(command.split())
        self.active_processes.append(child)
        return child

    def start_radius(self):
        """Start Radius Server"""
        # NOTE: RADIUS PORT and IP have not been set due to it
        # skipping sections of the radiusd.conf file when given.
        return self.run_command_and_detach("freeradius -X -l stdout", self.freeradius_log)

    def start_chewie(self):
        """Start Chewie Server"""

        self.chewie_pid = os.fork()
        if self.chewie_pid == 0:
            file = open(os.path.join(self.current_log_dir + "chewie.log"), 'w+')
            logger = get_logger('CHEWIE', file)
            logger.info('Starting chewie.')
            chewie = Chewie(CHEWIE_SUPPLICANT.name, logger, auth_handler,
                            failure_handler, logoff_handler,
                            radius_server_ip=RADIUS_IP, radius_server_secret=RADIUS_SECRET)
            chewie.run()

    def start_wpa_supplicant(self, eap_method):
        """Start WPA_Supplicant / EAP Client"""
        return self.run_command_and_detach(
            "wpa_supplicant -dd -c/tmp/wpasupplicant/wired-{}.conf -i{} -Dwired".format(
                eap_method, SUPPLICANT.name), self.wpa_supplicant_log)

    def start_dhclient(self):
        """Start dhclient on the MAB port"""
        return self.run_command_and_detach("dhclient -i {}".format(SUPPLICANT.name))

    def check_output(self, **kwargs):  # pylint: disable=no-self-use
        """Check the output of the Log Files to verify state of system"""

        with open(os.path.join(self.current_log_dir + "chewie.log"), "r") as file:
            chewie_log = file.read()

        chewie_requirements = kwargs.get("chewie_requirements", None)
        if chewie_requirements:
            for requirement in chewie_requirements:
                assert requirement in chewie_log, "Unable to find {} in chewie logs".format(
                    requirement, )

        assert "Authentication successful" in chewie_log, \
            "Authentication failed for {}".format(inspect.currentframe().f_back.f_code.co_name)


    @staticmethod
    def prepare_freeradius():
        chewie_rad_dir = CHEWIE_CONF_DIR + "freeradius/"
        if os.path.isfile('/etc/freeradius/users'):
            # Assume we are dealing with freeradius < 3
            radius_config_base = '/etc/freeradius/'
        else:
            # Assume we are dealing with freeradius >=3 configuration
            freerad_version = os.popen(
                r'freeradius -v | egrep -o -m 1 "Version ([0-9]\.[0.9])"').read().rstrip()
            freerad_major_version = freerad_version.split(' ')[1]
            radius_config_base = '/etc/freeradius/%s/' % freerad_major_version

        try:
            # Copy files
            file_map = {
                chewie_rad_dir + 'clients.conf': radius_config_base,
                chewie_rad_dir + 'users': radius_config_base,
                chewie_rad_dir + 'default/eap': radius_config_base + 'mods-available/',
                chewie_rad_dir + 'default/inner-eap': radius_config_base + 'mods-available/',
                chewie_rad_dir + 'default/tls': radius_config_base + 'sites-available/',
            }

            for src, dst in file_map.items():
                shutil.copy(src, dst)

            # Copy Folder
            folder_map = {
                chewie_rad_dir + 'certs': radius_config_base + 'certs',
            }
            for src, dst in folder_map.items():
                if os.path.exists(dst) and os.path.isdir(dst):
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)

        except OSError as err:
            print("Unable to copy FreeRadius files into place.", file=sys.stderr)
            raise err

    @staticmethod
    def prepare_wpa_supplicant():
        folder_map = {
            CHEWIE_CONF_DIR + 'wpasupplicant/': '/tmp/wpasupplicant',
            CHEWIE_CONF_DIR + 'wpasupplicant/cert': '/tmp/cert'
        }
        for src, dst in folder_map.items():
            if os.path.exists(dst) and os.path.isdir(dst):
                shutil.rmtree(dst)
            shutil.copytree(src, dst)

