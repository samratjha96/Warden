from __future__ import annotations

from urllib.parse import urlparse


SUPPORTED_HOSTS = {"github.com": "github", "gitlab.com": "gitlab"}


def parse_repo_url(raw_url: str) -> dict[str, str]:
    """Parse and validate a GitHub/GitLab repository URL."""
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("Repository URL is required")

    normalized = raw_url.strip()
    if not normalized:
        raise ValueError("Repository URL is required")

    if "://" not in normalized:
        normalized = "https://" + normalized

    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    provider = SUPPORTED_HOSTS.get(host)
    if not provider:
        raise ValueError("Invalid repo URL")

    path_parts = [part for part in parsed.path.split("/") if part]
    if len(path_parts) < 2:
        raise ValueError("Invalid repo URL")

    owner = path_parts[0]
    repo = path_parts[1]

    if repo.endswith(".git"):
        repo = repo[:-4]

    if not owner or not repo:
        raise ValueError("Invalid repo URL")

    canonical_url = f"https://{host}/{owner}/{repo}"
    return {
        "url": canonical_url,
        "provider": provider,
        "owner": owner,
        "repo": repo,
    }
