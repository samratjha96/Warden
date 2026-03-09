import unittest
from pathlib import Path

from worker_trigger import build_worker_command, trigger_worker_for_job


class WorkerTriggerTests(unittest.TestCase):
    def test_build_worker_command(self):
        root = Path("/repo/root")
        command = build_worker_command(root, "chalk-chalk-1234abcd")
        self.assertEqual(
            command,
            [
                "uv",
                "run",
                "worker/worker.py",
                "--job",
                "chalk-chalk-1234abcd",
            ],
        )

    def test_trigger_worker_for_job_starts_detached_process(self):
        calls = {}

        def fake_spawn(**kwargs):
            calls.update(kwargs)
            return object()

        ok, error = trigger_worker_for_job(
            root_dir=Path("/repo/root"),
            job_id="chalk-chalk-1234abcd",
            spawn_fn=fake_spawn,
        )
        self.assertTrue(ok)
        self.assertEqual(error, "")
        self.assertEqual(
            calls["args"],
            ["uv", "run", "worker/worker.py", "--job", "chalk-chalk-1234abcd"],
        )
        self.assertTrue(calls["start_new_session"])
        self.assertEqual(calls["cwd"], "/repo/root")

    def test_trigger_worker_for_job_returns_error_on_spawn_failure(self):
        def failing_spawn(**kwargs):
            raise OSError("spawn failed")

        ok, error = trigger_worker_for_job(
            root_dir=Path("/repo/root"),
            job_id="chalk-chalk-1234abcd",
            spawn_fn=failing_spawn,
        )
        self.assertFalse(ok)
        self.assertIn("spawn failed", error)


if __name__ == "__main__":
    unittest.main()
