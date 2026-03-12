import unittest

from worker.report_contract import (
    build_report,
    normalize_metadata,
    validate_markdown_report,
)


class ReportContractTests(unittest.TestCase):
    def test_normalize_metadata_enforces_required_fields(self):
        with self.assertRaises(ValueError):
            normalize_metadata({"verdict": "approve"})

    def test_normalize_metadata_shapes_sidebar_fields(self):
        metadata = normalize_metadata(
            {
                "verdict": "APPROVE",
                "risk": "LOW",
                "keyFinding": "Clean supply chain posture",
                "commit": "abc123",
                "ecosystem": "Node.js/NPM",
                "stars": 12345,
                "forks": 987,
                "contributors": 17,
                "openIssues": 4,
                "created": "2019-01-15",
                "license": "MIT",
                "hasSecurityMd": True,
                "approvalConditions": ["Pin dependencies", "Run weekly audit"],
                "scores": {
                    "supplyChain": 88,
                    "runtimeSafety": 93,
                    "maintainability": 90,
                    "overall": 90,
                },
            }
        )

        self.assertEqual(metadata["verdict"], "approve")
        self.assertEqual(metadata["risk"], "low")
        self.assertEqual(metadata["stats"]["stars"], "12,345")
        self.assertEqual(metadata["stats"]["forks"], "987")
        self.assertEqual(metadata["approvalConditions"][0], "Pin dependencies")
        self.assertEqual(metadata["scores"]["overall"], 90)

    def test_build_report_and_validate_contract(self):
        metadata = normalize_metadata(
            {
                "verdict": "conditional",
                "risk": "medium",
                "keyFinding": "Needs tighter install controls",
                "commit": "def456",
                "ecosystem": "Node.js/NPM",
                "stars": 10,
                "forks": 2,
                "contributors": 1,
                "openIssues": 0,
                "created": "2024-01-01",
                "license": "MIT",
                "hasSecurityMd": False,
            }
        )
        report = build_report(
            job={
                "id": "owner-repo-abcd1234",
                "url": "https://github.com/owner/repo",
                "owner": "owner",
                "repo": "repo",
            },
            markdown_content="# Security Analysis: owner/repo",
            analyzed_date="2026-03-09",
            metadata=metadata,
        )
        validate_markdown_report(report)
        self.assertEqual(report["format"], "markdown")
        self.assertEqual(report["id"], "owner-repo-abcd1234")


    def test_normalize_metadata_missing_stats_produces_nulls(self):
        """When the agent omits stat fields (e.g. GitHub API failure), stats
        must be None/null rather than zero so the display shows '—'."""
        metadata = normalize_metadata(
            {
                "verdict": "approve",
                "risk": "low",
                "keyFinding": "Clean",
                "commit": "abc123",
                "ecosystem": "Node.js/npm",
                # stars, forks, contributors, openIssues intentionally absent
            }
        )
        self.assertIsNone(metadata["stats"]["stars"])
        self.assertIsNone(metadata["stats"]["forks"])
        self.assertIsNone(metadata["stats"]["contributors"])
        self.assertIsNone(metadata["stats"]["openIssues"])


if __name__ == "__main__":
    unittest.main()
