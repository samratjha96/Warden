import unittest
from pathlib import Path


class AnalysisPromptTemplateTests(unittest.TestCase):
    def test_prompt_includes_deep_security_checklist_sections(self):
        prompt = Path("worker/PROMPT.md").read_text()

        required_sections = [
            "## Required Workflow",
            "## Deep Security Checklist",
            "### 1) Repository and Ecosystem Baseline",
            "### 2) Network and External Communications",
            "### 3) Telemetry, Analytics, and Tracking",
            "### 4) Data Collection and Privacy Risk",
            "### 5) Code Safety and Suspicious Patterns",
            "### 6) Binary and Executable Artifact Review",
            "### 7) Dependency and Vulnerability Analysis",
            "### 8) Supply Chain and Install-Time Risk",
            "### 9) Permissions and Capability Analysis",
            "### 10) Build and Runtime Behavior Analysis",
            "### 11) Repository Trust and Maintainer Signals",
            "### 12) Red Flags Decision Gate",
        ]

        for section in required_sections:
            self.assertIn(section, prompt)

    def test_prompt_requires_structured_markdown_and_metadata_output(self):
        prompt = Path("worker/PROMPT.md").read_text()
        self.assertIn("## Markdown Output Contract", prompt)
        self.assertIn("## Metadata Tool Contract", prompt)
        self.assertIn("Call `write_metadata` exactly once", prompt)
        self.assertIn("approvalConditions", prompt)
        self.assertIn("scores", prompt)


if __name__ == "__main__":
    unittest.main()
