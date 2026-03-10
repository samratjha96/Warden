from __future__ import annotations

from pathlib import Path


def remove_report(index: dict, report_id: str) -> bool:
    """Remove a report from the index by id and return whether it changed."""
    reports = index.get("reports", [])
    original_len = len(reports)
    index["reports"] = [report for report in reports if report.get("id") != report_id]
    return len(index["reports"]) != original_len


def delete_report_files(reports_dir: Path, report_id: str) -> list[str]:
    """Delete JSON/Markdown artifacts for a report id and return removed paths."""
    removed: list[str] = []
    for suffix in (".json", ".md"):
        path = reports_dir / f"{report_id}{suffix}"
        if path.exists() and path.is_file():
            path.unlink()
            removed.append(str(path))
    return removed
