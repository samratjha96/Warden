import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def load_worker_module():
    env = {
        "WARDEN_MODEL": "test-model",
        "OPENAI_COMPATIBLE_ENDPOINT": "https://llm.example/v1",
        "NVIDIA_API_KEY": "test-key",
    }
    with patch.dict(os.environ, env, clear=False):
        return importlib.import_module("worker.worker")


class WorkerToolsSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.worker = load_worker_module()

    def test_bash_blocks_shell_metacharacters_and_environment_reads(self):
        self.assertIn("BLOCKED", self.worker.bash.invoke({"command": "env"}))
        self.assertIn("BLOCKED", self.worker.bash.invoke({"command": "ls; env"}))

    def test_read_file_rejects_paths_outside_analysis_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(self.worker, "CLONE_BASE", Path(tmp) / "analysis"):
                result = self.worker.read_file.invoke({"path": "/etc/passwd"})

        self.assertIn("outside allowed analysis paths", result)

    def test_write_file_allows_report_output_but_blocks_other_absolute_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            clone_base = Path(tmp) / "analysis"
            reports_dir = Path(tmp) / "reports"
            report_path = reports_dir / "report.md"
            with (
                patch.object(self.worker, "CLONE_BASE", clone_base),
                patch.object(self.worker, "REPORTS_DIR", reports_dir),
            ):
                allowed = self.worker.write_file.invoke(
                    {"path": str(report_path), "content": "ok"}
                )
                blocked = self.worker.write_file.invoke(
                    {"path": "/tmp/not-a-report.md", "content": "no"}
                )

        self.assertIn("Successfully wrote", allowed)
        self.assertIn("outside allowed analysis paths", blocked)

    def test_grep_rejects_unapproved_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            clone_base = Path(tmp) / "analysis"
            clone_base.mkdir()
            (clone_base / "a.py").write_text("needle\n")
            with patch.object(self.worker, "CLONE_BASE", clone_base):
                result = self.worker.grep.invoke(
                    {
                        "pattern": "needle",
                        "path": str(clone_base),
                        "flags": "--include=*.py; env",
                    }
                )

        self.assertIn("unsupported grep flag", result)


if __name__ == "__main__":
    unittest.main()
