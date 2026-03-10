import json
import unittest

from repo_stats import fetch_repo_stats


class RepoStatsTests(unittest.TestCase):
    def test_fetch_repo_stats_parses_github_metadata(self):
        responses = {
            "https://api.github.com/repos/owner/repo": json.dumps(
                {
                    "stargazers_count": 1234,
                    "forks_count": 56,
                    "open_issues_count": 7,
                    "created_at": "2021-05-06T12:34:56Z",
                    "license": {"spdx_id": "MIT"},
                }
            ),
            "https://api.github.com/repos/owner/repo/contributors?per_page=100": json.dumps(
                [{}, {}, {}]
            ),
        }

        stats = fetch_repo_stats(
            provider="github",
            owner="owner",
            repo="repo",
            fetch_text=lambda url: responses[url],
        )

        self.assertEqual(stats["stars"], 1234)
        self.assertEqual(stats["forks"], 56)
        self.assertEqual(stats["openIssues"], 7)
        self.assertEqual(stats["contributors"], 3)
        self.assertEqual(stats["created"], "2021-05-06")
        self.assertEqual(stats["license"], "MIT")

    def test_fetch_repo_stats_returns_empty_on_fetch_failure(self):
        stats = fetch_repo_stats(
            provider="github",
            owner="owner",
            repo="repo",
            fetch_text=lambda url: (_ for _ in ()).throw(OSError("boom")),
        )
        self.assertEqual(stats, {})


if __name__ == "__main__":
    unittest.main()
