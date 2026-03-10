from __future__ import annotations

from urllib.parse import urlparse


DEFAULT_OPTIONS = {
    "ecosystem": "auto",
    "severity": "low",
    "depth": "shallow",
}


def infer_provider(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    if host == "gitlab.com":
        return "gitlab"
    return "github"


def build_regeneration_options(report: dict) -> dict[str, str]:
    raw_options = report.get("options")
    if isinstance(raw_options, dict):
        return {
            "ecosystem": str(raw_options.get("ecosystem") or DEFAULT_OPTIONS["ecosystem"]),
            "severity": str(raw_options.get("severity") or DEFAULT_OPTIONS["severity"]),
            "depth": str(raw_options.get("depth") or DEFAULT_OPTIONS["depth"]),
        }

    ecosystem = str(report.get("ecosystem", "")).strip()
    if not ecosystem or ecosystem.lower() == "unknown":
        ecosystem = DEFAULT_OPTIONS["ecosystem"]

    return {
        "ecosystem": ecosystem,
        "severity": DEFAULT_OPTIONS["severity"],
        "depth": DEFAULT_OPTIONS["depth"],
    }


def build_regeneration_job(
    report: dict,
    *,
    steering: str,
    submitted_at: str,
) -> dict:
    job = {
        "id": report["id"],
        "url": report["url"],
        "provider": str(report.get("provider") or infer_provider(report["url"])),
        "owner": report["owner"],
        "repo": report["repo"],
        "status": "pending",
        "submitted": submitted_at,
        "options": build_regeneration_options(report),
        "regenerationOf": report["id"],
    }

    steering = steering.strip()
    if steering:
        job["steering"] = steering

    return job
