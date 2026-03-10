import unittest

from server import should_trigger_worker


class ServerDispatchPolicyTests(unittest.TestCase):
    def test_triggers_when_inflight_below_limit(self):
        self.assertTrue(should_trigger_worker(inflight_jobs=0, max_inflight_jobs=1))
        self.assertTrue(should_trigger_worker(inflight_jobs=1, max_inflight_jobs=2))

    def test_does_not_trigger_when_inflight_at_or_above_limit(self):
        self.assertFalse(should_trigger_worker(inflight_jobs=1, max_inflight_jobs=1))
        self.assertFalse(should_trigger_worker(inflight_jobs=3, max_inflight_jobs=2))


if __name__ == "__main__":
    unittest.main()
