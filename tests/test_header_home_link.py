import unittest
from pathlib import Path
import re


class HeaderHomeLinkTests(unittest.TestCase):
    def test_all_pages_link_masthead_title_to_home(self):
        pages = [
            "site/index.html",
            "site/queue.html",
            "site/reports.html",
            "site/report.html",
        ]

        pattern = re.compile(
            r'<div class="masthead-title">[\s\S]*?<a[^>]+href="index\.html"[\s\S]*?<h1>Warden</h1>',
            re.MULTILINE,
        )

        for page in pages:
            html = Path(page).read_text()
            self.assertRegex(html, pattern, msg=f"missing home title link in {page}")


if __name__ == "__main__":
    unittest.main()
