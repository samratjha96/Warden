import unittest

from github_trending import (
    build_trending_job,
    enqueue_trending_repos,
    parse_github_trending_repos,
    repo_was_recently_analyzed,
)


class GitHubTrendingTests(unittest.TestCase):
    def test_parse_github_trending_repos_extracts_unique_repo_links(self):
        html = """
        <html>
          <body>
            <article class="Box-row"><h2><a class="Link" href="/astral-sh/uv">astral-sh / uv</a></h2></article>
            <a href="/features">Features</a>
            <a href="/sponsors/explore">Sponsors</a>
            <h2><a href="/not-a/repo">outside article</a></h2>
            <article class="Box-row"><h2><a class="Link" href="/pallets/flask">pallets / flask</a></h2></article>
            <article class="Box-row"><h2><a class="Link" href="/astral-sh/uv">duplicate</a></h2></article>
            <a href="/pallets/flask/stargazers">stars</a>
            <a href="https://docs.github.com">docs</a>
            <a href="//github.com/customer-stories">stories</a>
          </body>
        </html>
        """

        repos = parse_github_trending_repos(html)

        self.assertEqual(
            repos,
            [
                {
                    "provider": "github",
                    "owner": "astral-sh",
                    "repo": "uv",
                    "url": "https://github.com/astral-sh/uv",
                },
                {
                    "provider": "github",
                    "owner": "pallets",
                    "repo": "flask",
                    "url": "https://github.com/pallets/flask",
                },
            ],
        )

    def test_recent_report_blocks_reprocessing_inside_window(self):
        reports_index = {
            "reports": [
                {
                    "provider": "github",
                    "owner": "Astral-SH",
                    "repo": "uv",
                    "analyzed": "2026-04-15",
                }
            ]
        }

        self.assertTrue(
            repo_was_recently_analyzed(
                reports_index,
                {"provider": "github", "owner": "astral-sh", "repo": "uv"},
                now_date="2026-04-29",
                dedupe_days=30,
            )
        )
        self.assertFalse(
            repo_was_recently_analyzed(
                reports_index,
                {"provider": "github", "owner": "astral-sh", "repo": "uv"},
                now_date="2026-04-29",
                dedupe_days=7,
            )
        )

    def test_enqueue_trending_repos_skips_recent_reports_and_active_queue(self):
        queue = {
            "jobs": [
                {
                    "id": "pallets-flask-existing",
                    "provider": "github",
                    "owner": "pallets",
                    "repo": "flask",
                    "status": "pending",
                }
            ]
        }
        reports_index = {
            "reports": [
                {
                    "provider": "github",
                    "owner": "astral-sh",
                    "repo": "uv",
                    "analyzed": "2026-04-15",
                }
            ]
        }
        repos = [
            {"provider": "github", "owner": "astral-sh", "repo": "uv", "url": "https://github.com/astral-sh/uv"},
            {"provider": "github", "owner": "pallets", "repo": "flask", "url": "https://github.com/pallets/flask"},
            {"provider": "github", "owner": "psf", "repo": "requests", "url": "https://github.com/psf/requests"},
        ]

        result = enqueue_trending_repos(
            queue,
            reports_index,
            repos,
            now_value="2026-04-29T12:00:00Z",
            dedupe_days=30,
        )

        self.assertEqual(result["enqueued"], ["psf-requests-8c3d0c7c"])
        self.assertEqual(result["skipped_recent"], ["astral-sh/uv"])
        self.assertEqual(result["skipped_active"], ["pallets/flask"])
        self.assertEqual(queue["jobs"][0]["owner"], "psf")
        self.assertEqual(queue["jobs"][0]["source"], "github_trending")

    def test_build_trending_job_is_deterministic_for_repo_and_time(self):
        job = build_trending_job(
            {"provider": "github", "owner": "psf", "repo": "requests", "url": "https://github.com/psf/requests"},
            submitted_at="2026-04-29T12:00:00Z",
        )

        self.assertEqual(job["id"], "psf-requests-8c3d0c7c")
        self.assertEqual(job["status"], "pending")
        self.assertEqual(job["options"]["depth"], "shallow")


if __name__ == "__main__":
    unittest.main()
