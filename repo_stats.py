from __future__ import annotations

import json
from urllib.parse import quote
from urllib.request import Request, urlopen


def _default_fetch_text(url: str) -> str:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "warden",
        },
    )
    with urlopen(request, timeout=10) as response:
        return response.read().decode("utf-8")


def _normalize_created(value: str) -> str:
    value = (value or "").strip()
    if len(value) >= 10:
        return value[:10]
    return "unknown"


def fetch_repo_stats(
    *,
    provider: str,
    owner: str,
    repo: str,
    fetch_text=_default_fetch_text,
) -> dict:
    try:
        if provider == "gitlab":
            project = quote(f"{owner}/{repo}", safe="")
            metadata = json.loads(
                fetch_text(f"https://gitlab.com/api/v4/projects/{project}")
            )
            contributors = json.loads(
                fetch_text(
                    f"https://gitlab.com/api/v4/projects/{project}/repository/contributors"
                )
            )
            return {
                "stars": int(metadata.get("star_count", 0)),
                "forks": int(metadata.get("forks_count", 0)),
                "contributors": len(contributors) if isinstance(contributors, list) else 0,
                "openIssues": int(metadata.get("open_issues_count", 0)),
                "created": _normalize_created(metadata.get("created_at", "")),
                "license": (
                    (metadata.get("license") or {}).get("name")
                    if isinstance(metadata.get("license"), dict)
                    else "unknown"
                )
                or "unknown",
            }

        metadata = json.loads(fetch_text(f"https://api.github.com/repos/{owner}/{repo}"))
        contributors = json.loads(
            fetch_text(f"https://api.github.com/repos/{owner}/{repo}/contributors?per_page=100")
        )
        license_info = metadata.get("license") or {}
        return {
            "stars": int(metadata.get("stargazers_count", 0)),
            "forks": int(metadata.get("forks_count", 0)),
            "contributors": len(contributors) if isinstance(contributors, list) else 0,
            "openIssues": int(metadata.get("open_issues_count", 0)),
            "created": _normalize_created(metadata.get("created_at", "")),
            "license": (
                license_info.get("spdx_id")
                if isinstance(license_info, dict)
                else "unknown"
            )
            or "unknown",
        }
    except Exception:
        return {}
