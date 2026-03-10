import unittest

from queue_drain import run_target_then_drain


class QueueDrainTests(unittest.TestCase):
    def test_runs_target_then_drains_backlog(self):
        calls = []

        def run_target(job):
            calls.append(("run", job["id"]))
            return True

        def drain_backlog():
            calls.append(("drain", "all"))

        result = run_target_then_drain(
            job={"id": "job-1"},
            run_target=run_target,
            drain_backlog=drain_backlog,
        )
        self.assertTrue(result)
        self.assertEqual(calls, [("run", "job-1"), ("drain", "all")])

    def test_drains_backlog_even_when_target_job_missing(self):
        calls = []

        def run_target(job):
            calls.append(("run", job["id"]))
            return True

        def drain_backlog():
            calls.append(("drain", "all"))

        result = run_target_then_drain(
            job=None,
            run_target=run_target,
            drain_backlog=drain_backlog,
        )
        self.assertFalse(result)
        self.assertEqual(calls, [("drain", "all")])


if __name__ == "__main__":
    unittest.main()
