import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from report_ops import delete_report_files, remove_report


class ReportOpsTests(unittest.TestCase):
    def test_remove_report_deletes_matching_item(self):
        index = {
            "reports": [
                {"id": "a", "owner": "x", "repo": "one"},
                {"id": "b", "owner": "x", "repo": "two"},
            ]
        }
        removed = remove_report(index, "a")
        self.assertTrue(removed)
        self.assertEqual([r["id"] for r in index["reports"]], ["b"])

    def test_remove_report_returns_false_when_missing(self):
        index = {"reports": [{"id": "only"}]}
        self.assertFalse(remove_report(index, "missing"))
        self.assertEqual(len(index["reports"]), 1)

    def test_delete_report_files_removes_json_and_markdown(self):
        with TemporaryDirectory() as tmp:
            reports_dir = Path(tmp)
            report_id = "owner-repo-abc12345"
            json_path = reports_dir / f"{report_id}.json"
            md_path = reports_dir / f"{report_id}.md"
            json_path.write_text("{}")
            md_path.write_text("# report")

            removed_paths = delete_report_files(reports_dir, report_id)

            self.assertEqual(
                set(Path(path).name for path in removed_paths),
                {json_path.name, md_path.name},
            )
            self.assertFalse(json_path.exists())
            self.assertFalse(md_path.exists())


if __name__ == "__main__":
    unittest.main()
