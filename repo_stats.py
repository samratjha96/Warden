from __future__ import annotations

import json
import time
from urllib.error import HTTPError
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


def _fetch_with_retry(
    url: str, fetch_text, max_retries: int = 3, base_delay: float = 2.0
) -> str:
    """Fetch with exponential backoff retry on rate limit errors."""
    for attempt in range(max_retries):
        try:
            return fetch_text(url)
        except HTTPError as e:
            if e.code == 403 or e.code == 429:  # Rate limited
                if attempt < max_retries - 1:
                    # Check if there's a Retry-After header
                    retry_after = e.headers.get("Retry-After")
                    if retry_after:
                        delay = float(retry_after)
                    else:
                        delay = base_delay * (2**attempt)  # Exponential backoff
                    
                    print(f"Rate limited on {url}, retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    continue
            raise
        except Exception:
            if attempt < max_retries - 1:
                delay = base_delay * (2**attempt)
                print(f"Error fetching {url}, retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(delay)
                continue
            raise
    raise Exception(f"Failed to fetch {url} after {max_retries} attempts")


def fetch_repo_stats(
    *,
    provider: str,
    owner: str,
    repo: str,
    fetch_text=_default_fetch_text,
    max_retries: int = 3,
) -> dict:
    """Fetch repository statistics with retry logic for rate limits.
    
    Returns empty dict {} only on unrecoverable errors.
    Retries with exponential backoff on rate limit errors (403, 429).
    """
    try:
        if provider == "gitlab":
            project = quote(f"{owner}/{repo}", safe="")
            metadata = json.loads(
                _fetch_with_retry(
                    f"https://gitlab.com/api/v4/projects/{project}",
                    fetch_text,
                    max_retries,
                )
            )
            contributors = json.loads(
                _fetch_with_retry(
                    f"https://gitlab.com/api/v4/projects/{project}/repository/contributors",
                    fetch_text,
                    max_retries,
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

        # GitHub
        metadata = json.loads(
            _fetch_with_retry(
                f"https://api.github.com/repos/{owner}/{repo}",
                fetch_text,
                max_retries,
            )
        )
        contributors = json.loads(
            _fetch_with_retry(
                f"https://api.github.com/repos/{owner}/{repo}/contributors?per_page=100",
                fetch_text,
                max_retries,
            )
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
    except Exception as e:
        print(f"ERROR: Failed to fetch repo stats for {provider}:{owner}/{repo}: {e}")
        return {}
