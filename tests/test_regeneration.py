import unittest
from pathlib import Path


class RegenerationFeatureTests(unittest.TestCase):
    def test_backend_reuses_report_id_and_carries_optional_steering(self):
        from regeneration import build_regeneration_job

        report = {
            "id": "owner-repo-abcd1234",
            "url": "https://github.com/owner/repo",
            "owner": "owner",
            "repo": "repo",
            "provider": "github",
            "ecosystem": "Node.js/TypeScript",
            "options": {
                "ecosystem": "npm",
                "severity": "high",
                "depth": "deep",
            },
        }

        job = build_regeneration_job(
            report,
            steering="Focus on authz and shell execution surfaces.",
            submitted_at="2026-03-09T12:00:00Z",
        )

        self.assertEqual(job["id"], report["id"])
        self.assertEqual(job["status"], "pending")
        self.assertEqual(job["regenerationOf"], report["id"])
        self.assertEqual(job["steering"], "Focus on authz and shell execution surfaces.")
        self.assertEqual(job["options"]["depth"], "deep")
        self.assertEqual(job["options"]["severity"], "high")

    def test_backend_defaults_regeneration_options_when_report_lacks_them(self):
        from regeneration import build_regeneration_job

        report = {
            "id": "owner-repo-abcd1234",
            "url": "https://gitlab.com/owner/repo",
            "owner": "owner",
            "repo": "repo",
            "ecosystem": "unknown",
        }

        job = build_regeneration_job(
            report,
            steering="",
            submitted_at="2026-03-09T12:00:00Z",
        )

        self.assertEqual(job["provider"], "gitlab")
        self.assertNotIn("steering", job)
        self.assertEqual(
            job["options"],
            {"ecosystem": "auto", "severity": "low", "depth": "shallow"},
        )

    def test_frontend_exposes_regeneration_action_and_steering_input(self):
        script = Path("site/js/app.js").read_text()
        reports_page = Path("site/reports.html").read_text()
        index_page = Path("site/index.html").read_text()

        self.assertIn("function requestReportRegeneration", script)
        self.assertIn("/api/reports/' + encodeURIComponent(reportId) + '/regenerate", script)
        self.assertIn("regeneration-steering", script)
        self.assertIn("window.regenerateReportItem", reports_page)
        self.assertIn("window.regenerateReportItem", index_page)
        self.assertIn("title=\"Regenerate analysis\"", script)
        self.assertIn("aria-label=\"Regenerate analysis\"", script)

    def test_server_uses_report_index_loader_for_regeneration_source(self):
        server = Path("server.py").read_text()
        self.assertIn("load_report_by_id", server)
        self.assertIn("report = load_report_by_id(report_id)", server)


if __name__ == "__main__":
    unittest.main()
