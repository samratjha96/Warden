import unittest

from submission_limits import SubmissionLimiter


class SubmissionLimiterTests(unittest.TestCase):
    def test_blocks_back_to_back_submissions_with_debounce(self):
        limiter = SubmissionLimiter(
            min_interval_seconds=1.0,
            window_seconds=60,
            max_submissions_per_window=10,
        )

        allowed, code, retry_after = limiter.allow(now=100.0)
        self.assertTrue(allowed)
        self.assertEqual(code, "")
        self.assertEqual(retry_after, 0)

        allowed, code, retry_after = limiter.allow(now=100.2)
        self.assertFalse(allowed)
        self.assertEqual(code, "submit_debounced")
        self.assertEqual(retry_after, 1)

    def test_blocks_when_window_rate_limit_is_exceeded(self):
        limiter = SubmissionLimiter(
            min_interval_seconds=0.0,
            window_seconds=10,
            max_submissions_per_window=2,
        )

        self.assertEqual(limiter.allow(now=1.0), (True, "", 0))
        self.assertEqual(limiter.allow(now=2.0), (True, "", 0))

        allowed, code, retry_after = limiter.allow(now=3.0)
        self.assertFalse(allowed)
        self.assertEqual(code, "submit_rate_limited")
        self.assertEqual(retry_after, 8)

    def test_allows_again_after_window_expires(self):
        limiter = SubmissionLimiter(
            min_interval_seconds=0.0,
            window_seconds=10,
            max_submissions_per_window=1,
        )

        self.assertEqual(limiter.allow(now=1.0), (True, "", 0))
        self.assertEqual(limiter.allow(now=5.0), (False, "submit_rate_limited", 6))
        self.assertEqual(limiter.allow(now=12.1), (True, "", 0))


if __name__ == "__main__":
    unittest.main()
