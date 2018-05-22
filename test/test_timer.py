import unittest

from chewie.timer import Timer

class TimerTestCase(unittest.TestCase):
    def test_timer_is_off_by_default(self):
        timer = Timer(60)
        self.assertFalse(timer.running())

    def test_timer_expires(self):
        base_tick = 10000
        timer_count = 60
        timer = Timer(timer_count)
        self.assertFalse(timer.expired(base_tick))
        self.assertFalse(timer.expired(base_tick+timer_count-1))
        self.assertFalse(timer.expired(base_tick+timer_count+1))
        timer.reset(base_tick)
        self.assertTrue(timer.running())
        self.assertFalse(timer.expired(base_tick))
        self.assertFalse(timer.expired(base_tick+timer_count-1))
        self.assertTrue(timer.expired(base_tick+timer_count+1))
        timer.stop()
        self.assertFalse(timer.expired(base_tick))
        self.assertFalse(timer.expired(base_tick+timer_count-1))
        self.assertFalse(timer.expired(base_tick+timer_count+1))
