"""Unittests for eap_state_machine.FullEAPStateMachine"""
# pylint: disable=missing-docstring

import logging
from queue import Queue
import tempfile
import unittest

from chewie.eap import Eap
from chewie.eap_state_machine import FullEAPStateMachine
from chewie.event import EventMessageReceived, EventRadiusMessageReceived, EventPortStatusChange
from chewie.mac_address import MacAddress
from chewie.message_parser import EapolStartMessage, IdentityMessage, Md5ChallengeMessage, \
    SuccessMessage, LegacyNakMessage, TtlsMessage, FailureMessage, EapolLogoffMessage
from chewie.radius_attributes import State
from helpers import FakeTimerScheduler


def check_counters(_func=None, *,
                   expected_auth_counter=0, expected_failure_counter=0, expected_logoff_counter=0):
    """Decorator to check the handlers have been called the
     correct number of times at the end of each test"""
    def decorator_check_counters(func):
        def wrapper(self):

            start_auth_counter = self.auth_counter
            start_failure_counter = self.failure_counter
            start_logoff_counter = self.logoff_counter
            ret = func(self)
            self.assertEqual(self.auth_counter,
                             start_auth_counter + expected_auth_counter)
            self.assertEqual(self.failure_counter,
                             start_failure_counter + expected_failure_counter)
            self.assertEqual(self.logoff_counter,
                             start_logoff_counter + expected_logoff_counter)
            return ret

        return wrapper
    if _func is None:
        return decorator_check_counters
    else:
        return decorator_check_counters(_func)


class FullStateMachineStartTestCase(unittest.TestCase):
    # TODO tests could be more thorough, and test that
    # the correct packet (type/content) has been put in its respective queue.
    # Would also be nice to check that the states are correctly transitioned through,
    # and not just the final resting spot. Not sure how to do that - maybe parse the log??

    PORT_ID_MAC = MacAddress.from_string("00:00:00:00:00:01")

    def setUp(self):
        logger = logging.getLogger()
        logger.level = logging.DEBUG
        self.log_file = tempfile.NamedTemporaryFile()
        logger.addHandler(logging.FileHandler(self.log_file.name))

        self.eap_output_queue = Queue()
        self.radius_output_queue = Queue()
        self.timer_scheduler = FakeTimerScheduler()
        self.src_mac = MacAddress.from_string("00:12:34:56:78:90")
        log_prefix = "chewie.SM - port: %s, client: %s" % (self.src_mac, self.PORT_ID_MAC)

        self.sm = FullEAPStateMachine(self.eap_output_queue, self.radius_output_queue, self.src_mac,
                                      self.timer_scheduler,
                                      self.auth_handler, self.failure_handler, self.logoff_handler,
                                      log_prefix)
        # find ways to inject these - overriding consts isn't ideal
        self.MAX_RETRANSMITS = 3
        self.sm.MAX_RETRANS = self.MAX_RETRANSMITS
        self.sm.DEFAULT_TIMEOUT = 0.1
        self.sm.port_enabled = True
        self.sm.eap_restart = True

        self.auth_counter = 0
        self.failure_counter = 0
        self.logoff_counter = 0

    def tearDown(self):
        with open(self.log_file.name) as log:
            self.assertNotIn('aaaEapResp is true. but data is false. This should never happen',
                             log.read())

    def auth_handler(self, client_mac, port_id_mac, timer, vlan_name, filter_id):  # pylint: disable=unused-argument
        self.auth_counter += 1
        print('Successful auth from MAC %s' % str(client_mac))

    def failure_handler(self, client_mac, port_id_mac):  # pylint: disable=unused-argument
        self.failure_counter += 1
        print('failure from MAC %s' % str(client_mac))

    def logoff_handler(self, client_mac, port_id_mac):  # pylint: disable=unused-argument
        self.logoff_counter += 1
        print('logoff from MAC %s' % str(client_mac))

    @check_counters
    def test_eap_start(self):
        # input EAPStart packet.
        # output EAPIdentityRequest on eap_output_q
        message = EapolStartMessage(self.src_mac)
        self.sm.event(EventMessageReceived(message, self.PORT_ID_MAC))
        self.assertEqual(self.sm.state, self.sm.IDLE)

        self.assertEqual(self.eap_output_queue.qsize(), 1)
        output = self.eap_output_queue.get_nowait()[0]
        self.assertIsInstance(output, IdentityMessage)
        self.assertEqual(self.radius_output_queue.qsize(), 0)

        return output  # Used by test_identity_response

    @check_counters
    def test_eap_restart(self):
        self.test_eap_start()
        message = EapolStartMessage(self.src_mac)
        self.sm.event(EventMessageReceived(message, self.PORT_ID_MAC))
        self.assertEqual(self.sm.state, self.sm.IDLE)

        self.assertEqual(self.eap_output_queue.qsize(), 1)
        output = self.eap_output_queue.get_nowait()[0]
        self.assertIsInstance(output, IdentityMessage)
        self.assertEqual(self.radius_output_queue.qsize(), 0)

    @check_counters
    def test_no_radius_state_attribute_after_restart(self):
        """The RADIUS State Attribute is returned by the RADIUS server,
        and MUST be sent back in the next RADIUS Message.
        Unless the authentication process has been restarted or its a new one.
        Here we restart part way through another."""
        self.test_md5_challenge_request()

        self.assertEqual(self.sm.radius_state_attribute.data_type.data(), b'random state')

        self.test_eap_restart()
        self.assertIsNone(self.sm.radius_state_attribute)

    @check_counters
    def test_timeout_failure_from_max_retransmits(self):
        """Go to timeout failure from exceeding max retransmits (also tests retransmitting)"""
        output0 = self.test_eap_start()

        old_radius_count = self.radius_output_queue.qsize()
        self.timer_scheduler.run_jobs()

        output1 = self.eap_output_queue.get_nowait()[0]
        output2 = self.eap_output_queue.get_nowait()[0]
        output3 = self.eap_output_queue.get_nowait()[0]
        self.assertIsInstance(output0, IdentityMessage)
        self.assertIsInstance(output1, IdentityMessage)
        self.assertEqual(output0, output1)
        self.assertEqual(output0, output2)
        self.assertEqual(output0, output3)
        self.assertEqual(self.radius_output_queue.qsize(), 0)

        self.assertEqual(self.sm.state, self.sm.TIMEOUT_FAILURE)
        self.assertEqual(self.eap_output_queue.qsize(), 0)
        self.assertEqual(old_radius_count, self.radius_output_queue.qsize())

    @check_counters(expected_auth_counter=1)
    def test_auth_success_after_timeout_failure2_from_max_retransmits(self):
        self.test_timeout_failure2_from_max_retransmits()
        self.eap_output_queue.queue.clear()
        self.test_success2()

    @check_counters(expected_auth_counter=1)
    def test_auth_success_after_timeout_failure2_from_aaa_timeout(self):
        self.test_timeout_failure2_from_aaa_timeout()
        self.test_success2()

    @check_counters(expected_auth_counter=1)
    def test_auth_success_after_timeout_failure_after_max_retransmits(self):
        self.test_timeout_failure_from_max_retransmits()
        self.test_success2()

    @check_counters()
    def test_leave_timeout_failure2_with_identiy_response(self):
        self.test_timeout_failure2_from_max_retransmits()
        start_eap_q_size = self.eap_output_queue.qsize()
        start_radius_q_size = self.radius_output_queue.qsize()
        message = IdentityMessage(self.src_mac, 25, Eap.RESPONSE, "host1user")
        self.sm.event(EventMessageReceived(message, self.PORT_ID_MAC))
        self.assertEqual(self.sm.state, self.sm.AAA_IDLE)

        self.assertEqual(self.eap_output_queue.qsize(), start_eap_q_size + 0)
        self.assertEqual(self.radius_output_queue.qsize(), start_radius_q_size + 1)
        self.assertIsInstance(self.radius_output_queue.get_nowait()[0], IdentityMessage)


    @check_counters
    def test_timeout_failure2_from_aaa_timeout(self):
        """no response from AAA server equals timeout_failure2"""
        self.test_md5_challenge_response()
        old_eap_count = self.eap_output_queue.qsize()
        old_radius_count = self.radius_output_queue.qsize()

        self.timer_scheduler.run_jobs()

        self.assertEqual(self.sm.state, self.sm.TIMEOUT_FAILURE2)
        self.assertEqual(old_eap_count, self.eap_output_queue.qsize())
        self.assertEqual(old_radius_count, self.radius_output_queue.qsize())

    @check_counters
    def test_timeout_failure2_from_max_retransmits(self):
        """If client does not respond when in passthrough mode,
         send again and again until max retransmit counter is reached."""
        self.test_md5_challenge_request()
        self.assertEqual(self.eap_output_queue.qsize(), 0)
        old_radius_count = self.radius_output_queue.qsize()

        self.timer_scheduler.run_jobs()

        self.assertEqual(self.sm.state, self.sm.TIMEOUT_FAILURE2)
        self.assertEqual(self.MAX_RETRANSMITS, self.eap_output_queue.qsize())
        self.assertEqual(old_radius_count, self.radius_output_queue.qsize())

    @check_counters(expected_auth_counter=1)
    def test_disabled_state(self):
        """move to disabled and then from disabled"""
        self.test_success2()
        # move to disabled. e.g. link down.
        self.sm.event(EventPortStatusChange(False))
        self.assertEqual(self.sm.state, self.sm.DISABLED)

        self.assertEqual(self.eap_output_queue.qsize(), 0)
        self.assertEqual(self.radius_output_queue.qsize(), 0)
        self.assertEqual(self.auth_counter, 1)
        # don't transition to initialize (still not enabled)
        message = EapolStartMessage(self.src_mac)
        self.sm.event(EventMessageReceived(message, self.PORT_ID_MAC))

        self.assertEqual(self.sm.state, self.sm.DISABLED)
        self.assertEqual(self.eap_output_queue.qsize(), 0)
        self.assertEqual(self.radius_output_queue.qsize(), 0)

        # port is enabled again
        self.sm.event(EventPortStatusChange(True))

        self.assertEqual(self.sm.state, self.sm.IDLE)

        self.assertEqual(self.eap_output_queue.qsize(), 1)
        self.assertEqual(self.radius_output_queue.qsize(), 0)

    @check_counters
    def test_identity_response(self):
        _id = self.test_eap_start().message_id
        # input EapIdentityResponse
        # output EapIdentityResponse on radius_output_q
        message = IdentityMessage(self.src_mac, _id, Eap.RESPONSE, "host1user")
        self.sm.event(EventMessageReceived(message, self.PORT_ID_MAC))

        self.assertEqual(self.sm.state, self.sm.AAA_IDLE)

        self.assertEqual(self.eap_output_queue.qsize(), 0)
        self.assertEqual(self.radius_output_queue.qsize(), 1)
        self.assertIsInstance(self.radius_output_queue.get_nowait()[0], IdentityMessage)

    @check_counters
    def test_md5_challenge_request(self):
        self.test_identity_response()

        eap_message = Md5ChallengeMessage(self.src_mac, 2, Eap.REQUEST,
                                          bytes.fromhex("74d3db089b727d9cc5774599e4a32a29"),
                                          b"host1user")
        self.sm.event(EventRadiusMessageReceived(eap_message, State.create(b"random state")))

        self.assertEqual(self.sm.state, self.sm.IDLE2)

        self.assertEqual(self.eap_output_queue.qsize(), 1)
        output = self.eap_output_queue.get_nowait()[0]
        self.assertIsInstance(output, Md5ChallengeMessage)

        self.assertEqual(self.radius_output_queue.qsize(), 0)
        return output

    @check_counters
    def test_md5_challenge_response(self):
        self.test_md5_challenge_request()

        message = Md5ChallengeMessage(self.src_mac, 2, Eap.RESPONSE,
                                      bytes.fromhex("3a535f0ee8c6b34fe714aa7dad9a0e15"),
                                      b"host1user")
        self.sm.event(EventMessageReceived(message, self.PORT_ID_MAC))

        self.assertEqual(self.sm.state, self.sm.AAA_IDLE)
        self.assertEqual(self.eap_output_queue.qsize(), 0)
        self.assertEqual(self.radius_output_queue.qsize(), 1)
        self.assertIsInstance(self.radius_output_queue.get_nowait()[0], Md5ChallengeMessage)

    @check_counters(expected_auth_counter=1)
    def test_success2(self):
        self.test_md5_challenge_response()

        message = SuccessMessage(self.src_mac, 3)
        self.sm.event(EventRadiusMessageReceived(message, None))

        self.assertEqual(self.sm.state, self.sm.SUCCESS2)
        self.assertEqual(self.eap_output_queue.qsize(), 1)
        self.assertIsInstance(self.eap_output_queue.get_nowait()[0], SuccessMessage)
        self.assertEqual(self.radius_output_queue.qsize(), 0)

    @check_counters(expected_auth_counter=2)
    def test_two_success2(self):
        self.test_success2()

        expiry_job = self.sm.session_timeout_job
        self.assertFalse(expiry_job.cancelled())

        self.test_success2()
        self.assertTrue(expiry_job.cancelled())

        expiry_job = self.sm.session_timeout_job
        self.assertFalse(expiry_job.cancelled())

    @check_counters(expected_auth_counter=2, expected_logoff_counter=1)
    def test_logoff2(self):
        """Test logoff from success2 state."""
        self.test_success2()

        # test the second logon expires the firsts session timeout event.
        expiry_job = self.sm.session_timeout_job
        self.assertFalse(expiry_job.cancelled())

        message = EapolLogoffMessage(self.src_mac)
        self.sm.event(EventRadiusMessageReceived(message, self.PORT_ID_MAC))

        self.assertTrue(expiry_job.cancelled())

        self.assertEqual(self.sm.state, self.sm.LOGOFF2)
        self.assertEqual(self.eap_output_queue.qsize(), 0)
        self.assertEqual(self.radius_output_queue.qsize(), 0)

        self.test_success2()

    @check_counters
    def test_logoff_from_idle2(self):
        """Test logoff from middle of authentication. should be ignored"""
        self.test_md5_challenge_request()

        message = EapolLogoffMessage(self.src_mac)
        self.sm.event(EventRadiusMessageReceived(message, self.PORT_ID_MAC))

        # should be in same state as when test_md5_challenge_request returned.

        self.assertEqual(self.sm.state, self.sm.IDLE2)
        self.assertEqual(self.eap_output_queue.qsize(), 0)
        self.assertEqual(self.radius_output_queue.qsize(), 0)

    @check_counters(expected_failure_counter=1)
    def test_failure2(self):
        self.test_md5_challenge_response()
        message = FailureMessage(self.src_mac, 3)
        self.sm.event(EventRadiusMessageReceived(message, None))

        self.assertEqual(self.sm.state, self.sm.FAILURE2)
        self.assertEqual(self.eap_output_queue.qsize(), 1)
        self.assertIsInstance(self.eap_output_queue.get_nowait()[0], FailureMessage)
        self.assertEqual(self.radius_output_queue.qsize(), 0)

    @check_counters
    def test_discard2(self):
        request = self.test_md5_challenge_request()

        message = Md5ChallengeMessage(self.src_mac, request.message_id + 10, Eap.RESPONSE,
                                      bytes.fromhex("3a535f0ee8c6b34fe714aa7dad9a0e15"),
                                      b"host1user")
        self.sm.event(EventMessageReceived(message, self.PORT_ID_MAC))
        self.assertEqual(self.sm.state, self.sm.IDLE2)
        self.assertEqual(self.eap_output_queue.qsize(), 0)
        self.assertEqual(self.radius_output_queue.qsize(), 0)

    @check_counters
    def test_discard(self):
        message = self.test_eap_start()
        # Make a message that will be discarded (id here is not sequential)
        message = IdentityMessage(self.src_mac, message.message_id + 10, Eap.RESPONSE, "host1user")
        self.sm.event(EventMessageReceived(message, self.PORT_ID_MAC))
        self.assertEqual(self.sm.state, self.sm.IDLE)

        self.assertEqual(self.eap_output_queue.qsize(), 0)
        self.assertEqual(self.radius_output_queue.qsize(), 0)

    @check_counters
    def test_ttls_request(self):
        self.test_md5_challenge_request()
        self.assertEqual(self.eap_output_queue.qsize(), 0)
        self.assertEqual(self.radius_output_queue.qsize(), 0)

        message = LegacyNakMessage(self.src_mac, 2, Eap.RESPONSE, 21)
        self.sm.event(EventMessageReceived(message, self.PORT_ID_MAC))
        self.assertEqual(self.sm.state, self.sm.AAA_IDLE)
        self.assertEqual(self.eap_output_queue.qsize(), 0)
        self.assertEqual(self.radius_output_queue.qsize(), 1)

        message = TtlsMessage(self.src_mac, 3, Eap.REQUEST, 0x20, b'')
        self.sm.event(EventRadiusMessageReceived(message, State.create(b"more random state")))
        self.assertEqual(self.sm.state, self.sm.IDLE2)
        self.assertEqual(self.eap_output_queue.qsize(), 1)
        self.assertEqual(self.radius_output_queue.qsize(), 1)

        message = TtlsMessage(self.src_mac, 3, Eap.RESPONSE, 0x00,
                              bytes.fromhex('16030101280100012403032c36dbf8ee16b94b28efdb8c5603e07823f9b716557b5ef2624b026daea115760000aac030c02cc028c024c014c00a00a500a300a1009f006b006a0069006800390038003700360088008700860085c032c02ec02ac026c00fc005009d003d00350084c02fc02bc027c023c013c00900a400a200a0009e00670040003f003e0033003200310030009a0099009800970045004400430042c031c02dc029c025c00ec004009c003c002f00960041c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff01000051000b000403000102000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101'))
        self.sm.event(EventMessageReceived(message, self.PORT_ID_MAC))
        self.assertEqual(self.sm.state, self.sm.AAA_IDLE)
        self.assertEqual(self.eap_output_queue.qsize(), 1)
        self.assertEqual(self.radius_output_queue.qsize(), 2)

        message = TtlsMessage(self.src_mac, 4, Eap.REQUEST, 0x00, bytes.fromhex(
            '160303003e0200003a03036bf75d277e59b04228197af91c1c32c78beb8a708193ab3ac23a9aed30f5390c00c030000012ff01000100000b000403000102000f00010116030308d30b0008cf0008cc0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c6520436572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cf5456d7e6142383101cf79275f6396e2c9b3f7cb2878d35e5ecc6f47ee11ef20bc8a8b3217a89351c55856e5cd5eed2d10037c9bcce89fbdf927e4cc4f069863acbac4accee7e80f2105ad80d837fa50a931c5b41d03c993f5e338cfd8e69e23818360053501c34c08132ec3d6e14df89ff29c5cec5c7a87d48c4afdcf9d3f8290050be5b903ba6a2a5ce2eb79c922cae70869618c75923059f9a8d62144e8ecdaf0a9f02886afa0e73e3d68037ea9fdca2bdd0f0785e05f5ac88031010c105575dbb09eb4f307547622120ee384ab454376de8e14e0afea02f1211801b6c932324ef6dba7abf3f48f8e3e84716c40b59041ec936cb273d684b22aa1c9d24e10203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b0500038201010054fdcdabdc3a153dc167d6b210d1b324ecfac0e3b8d385704463a7f8ebf46e2e6952f249f4436ec66760868860e5ed50b519ec14628179472c312f507bc9349971d21f8f2b7d6b329b02fab448bd90fd4ce4dfbc78f23a8c4eed74d5589f4c3bd11b552535b8ab8a1a6ab9d1dfda21f247a93354702c12fdde1113cb8dd0e46e2a3a94547c9871df2a88943751d8276dc43f7f6aed921f43f6a33f9beba804c3d2b5781d754abe36ba58461798be8585b8b24b5c4a26d1e0905eb5bbae6e139b06728406bfe31baa27852252c7b4711c35ec9a41945488ef8c79a8a201351189e65baed66300528b45dfbcad233cd045336d5b35331ee76360b58583884eb0aa0004e8308204e4308203cca003020102020900de5bbe2e4d41d7fd300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c6520436572746966696361746520417574686f72697479301e170d3138303630353033353134345a170d3138303830343033353134345a308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c6520436572746966696361746520417574686f7269747930820122300d06092a864886f70d01010105000382010f003082010a02820101009b2190c32456e96ad8d08c6577839dcaf819f98a104bad079330714b7c12c765861c9a2e74eb0aec87a64eb58caa781f543eb2971db6b9e3b662952213aaf806fbb38c7a7fa46135c14a2e0e0a158162c2414e3c3f835bf4b80007c03df51746a04715dada1fb9fb155d479da9c34e40f192c65f64b16d4c742e66cbdc748ce0763cd45b7a88ff7d99d66449676a07116651394107c2ab5d654ad9a0315b78a2342a26790629fbe1e19a734e5e2eab933f3cef3e81c4413443988c8ccd9bc35b7ba3c6ec5571f4089ab07e401b2f21131316d4f8333782acc76d661f8440287c8e0a122200d9067b6b5d2af4cd5ab23f69cd689652c813fdd04f4f83544b4d450203010001a382013730820133301d0603551d0e0416041473fd7fcd4adc85cbfd85734c722335e7472b8df03081c80603551d230481c03081bd801473fd7fcd4adc85cbfd85734c722335e7472b8df0a18199a48196308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c6520436572746966696361746520417574686f72697479820900de5bbe2e4d41d7fd300f0603551d130101ff040530030101ff30360603551d1f042f302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e6f72672f6578616d706c655f63612e63726c300d06092a864886f70d01010b05000382010100139e9c2b1e9bf30c6567759ffb57af9f031a59b6a8adb1702a55de2e51f2286715ef1399ebdc593d38db3ad4794c3e78037d3de5612cba33cefc5b830c3a2118bfc0572d201c07105b7c0ef5bb64225d959afef6a4527a88d1e5fd552fd16775a5c90802d11ad793da157441f7a181f85a2908ebcb87a86960c6d3ae631019bc73f850bc5be494a97084ccaea1cc13c44a4fdf0ef123c067b688e47a4d223c15fd56798051ff4912c721f15c96061ef683b1ade02b5449b06184f59d4218f2287d35cfa0a3a4f65e40c8750d0c70dc00d65a8981e0a2cf6961b1355c10d399ce583a426e211b0feef37da67a57bbbc81d912d5379668cfdc3666bacf5e9d9c7d160303014d0c0001490300174104b275c284c5c067b9c3104305ba6704b4b0e083f0e285d9b205a8d7307e503907478f314679d084a0f1ccbc3ceaa6b6d56c588654d223fd16514bba463c5f8d7006010100bca760ef9aab5f1cf9239bab7d0bbf585e12f9c6440b9dd36affc87ff8f334b0dbea94686edbcff9143bd40a5136b065d5599742665fa27d5ec5e86898b7c8cc2c375d190646c644df7911f41a12a7219f667527cfc4ba99b684fb763a01f4dc361a891906e3ade0c6e787c096f868726a5aafafb76ce71ce896b50015c9db89e9c3d13c90e90b5d82a1327941404298c1e358cbc7bbbf8e4fe2e1ecafbcbddfbe0b1a7d3f0769306f16f3ed4972b14b8af0f51761053754ec73a1a41b294fe0d00a9281e3d9c0175651d2bbaf28df32a25bfbae85983a3935891f0a955b636b3540cde3aba4ec20d62988a81a608b450e87b3eefcb66f50cf3104a4b367122d16030300040e000000'))
        self.sm.event(EventRadiusMessageReceived(message, State.create(b"some more random state")))
        self.assertEqual(self.sm.state, self.sm.IDLE2)
        self.assertEqual(self.eap_output_queue.qsize(), 2)
        self.assertEqual(self.radius_output_queue.qsize(), 2)

    @check_counters(expected_auth_counter=1, expected_logoff_counter=1)
    def test_deauth_timer(self):
        self.sm.DEFAULT_SESSION_TIMEOUT = 2
        self.test_success2()

        self.timer_scheduler.run_jobs()
        self.assertEqual(self.sm.state, self.sm.LOGOFF2)

    @check_counters(expected_auth_counter=2, expected_logoff_counter=0)
    def test_port_flap(self):
        """Test logoff from success2 state."""
        self.test_success2()
        # Put port down
        self.sm.event(EventPortStatusChange(False))
        self.sm.event(EventPortStatusChange(True))

        self.assertEqual(self.sm.state, self.sm.NO_STATE)
        self.assertFalse(self.sm.aaa_success)
        self.assertFalse(self.sm.eap_success)

        self.assertEqual(self.eap_output_queue.qsize(), 0)
        self.assertEqual(self.radius_output_queue.qsize(), 0)

        self.test_success2()
