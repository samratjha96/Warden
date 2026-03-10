import unittest
from pathlib import Path


class QueueFreshnessTests(unittest.TestCase):
    def test_app_exposes_fresh_json_fetch_helper(self):
        script = Path("site/js/app.js").read_text()
        self.assertIn("function fetchJSONFresh", script)
        self.assertIn("cache: 'no-store'", script)

    def test_queue_page_uses_fresh_fetch_for_jobs(self):
        html = Path("site/queue.html").read_text()
        self.assertIn("App.fetchJSONFresh('data/queue/jobs.json')", html)

    def test_server_marks_runtime_json_as_non_cacheable(self):
        server = Path("server.py").read_text()
        self.assertIn("Cache-Control", server)
        self.assertIn("no-store", server)


if __name__ == "__main__":
    unittest.main()
