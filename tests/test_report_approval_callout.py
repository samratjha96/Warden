import unittest
from pathlib import Path


class ReportApprovalCalloutTests(unittest.TestCase):
    def test_app_exposes_approval_conditions_renderer(self):
        script = Path("site/js/app.js").read_text()
        self.assertIn("function renderApprovalConditionsCallout", script)
        self.assertIn("Approval Conditions", script)

    def test_report_page_uses_approval_conditions_callout_for_markdown_reports(self):
        html = Path("site/report.html").read_text()
        self.assertIn("App.renderApprovalConditionsCallout(report)", html)

    def test_report_page_sanitizes_markdown_before_inner_html(self):
        html = Path("site/report.html").read_text()
        self.assertIn("DOMPurify.sanitize", html)
        self.assertIn("marked.parse(content)", html)

    def test_report_page_uses_existing_marked_bundle(self):
        html = Path("site/report.html").read_text()
        self.assertIn("marked@16.4.2/lib/marked.umd.js", html)

    def test_styles_include_approval_callout(self):
        css = Path("site/css/brutal.css").read_text()
        self.assertIn(".approval-callout", css)
        self.assertIn(".approval-callout-title", css)


if __name__ == "__main__":
    unittest.main()
