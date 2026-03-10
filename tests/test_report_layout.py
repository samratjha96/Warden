import re
import unittest
from pathlib import Path


class ReportLayoutTests(unittest.TestCase):
    def test_report_grid_constrains_main_column(self):
        css = Path("site/css/brutal.css").read_text()
        self.assertRegex(
            css,
            re.compile(r"\.body-grid\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\)\s+360px;", re.DOTALL),
        )
        self.assertRegex(
            css,
            re.compile(r"\.main-col\s*\{[^}]*min-width:\s*0;", re.DOTALL),
        )

    def test_markdown_styles_wrap_long_inline_content(self):
        html = Path("site/report.html").read_text()
        self.assertRegex(
            html,
            re.compile(r"\.markdown-body\s*\{[^}]*overflow-wrap:\s*anywhere;", re.DOTALL),
        )
        self.assertRegex(
            html,
            re.compile(r"\.markdown-body code\s*\{[^}]*white-space:\s*normal;[^}]*overflow-wrap:\s*anywhere;", re.DOTALL),
        )

    def test_evidence_appendix_code_blocks_use_light_reference_treatment(self):
        html = Path("site/report.html").read_text()
        self.assertRegex(
            html,
            re.compile(r"\.markdown-body pre\.evidence-section-item\s*\{[^}]*background:\s*#efebe4;[^}]*color:\s*var\(--ink\);", re.DOTALL),
        )


if __name__ == "__main__":
    unittest.main()
