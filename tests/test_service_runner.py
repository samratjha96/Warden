import sys
import unittest

from service_runner import build_service_command


class ServiceRunnerTests(unittest.TestCase):
    def test_builds_server_command(self):
        self.assertEqual(build_service_command("server", ["13000"]), [sys.executable, "server.py", "13000"])

    def test_builds_worker_watch_command_by_default(self):
        self.assertEqual(build_service_command("worker", []), [sys.executable, "worker/worker.py", "--watch"])

    def test_builds_trending_watch_command_by_default(self):
        self.assertEqual(
            build_service_command("trending", []),
            [
                sys.executable,
                "github_trending.py",
                "--watch",
                "--interval-hours",
                "24",
                "--no-trigger-worker",
            ],
        )

    def test_builds_trending_command_with_explicit_args(self):
        self.assertEqual(
            build_service_command("trending", ["--max-repos", "5"]),
            [sys.executable, "github_trending.py", "--max-repos", "5"],
        )


if __name__ == "__main__":
    unittest.main()
