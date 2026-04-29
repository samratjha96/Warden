from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import time
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import fcntl

from queue_ops import enqueue_job
from worker_trigger import trigger_worker_for_job

ROOT_DIR = Path(__file__).parent.absolute()
SITE_DIR = ROOT_DIR / "site"
QUEUE_FILE = SITE_DIR / "data" / "queue" / "jobs.json"
QUEUE_LOCK_FILE = QUEUE_FILE.with_suffix(".json.lock")
REPORTS_INDEX_FILE = SITE_DIR / "data" / "reports" / "index.json"
REPORTS_LOCK_FILE = REPORTS_INDEX_FILE.with_suffix(".json.lock")
GITHUB_TRENDING_URL = "https://github.com/trending"
DEFAULT_MAX_REPOS = int(os.environ.get("TRENDING_MAX_REPOS", "10"))
DEFAULT_DEDUPE_DAYS = int(os.environ.get("TRENDING_DEDUPE_DAYS", "30"))
GITHUB_SITE_SECTIONS = {
    "about",
    "collections",
    "customer-stories",
    "enterprise",
    "events",
    "features",
    "login",
    "marketplace",
    "organizations",
    "orgs",
    "pricing",
    "readme",
    "signup",
    "solutions",
    "sponsors",
    "topics",
    "trending",
}


class TrendingRepoParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.repos: list[dict[str, str]] = []
        self._seen: set[tuple[str, str]] = set()
        self._article_depth = 0
        self._heading_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_by_name = dict(attrs)
        if tag == "article":
            classes = set(str(attrs_by_name.get("class", "")).split())
            if "Box-row" in classes:
                self._article_depth += 1
            return
        if tag == "h2" and self._article_depth > 0:
            self._heading_depth += 1
            return
        if tag != "a":
            return
        if self._article_depth <= 0 or self._heading_depth <= 0:
            return
        href = attrs_by_name.get("href")
        if not href:
            return
        if not href.startswith("/") or href.startswith("//"):
            return
        parts = [part for part in href.split("/") if part]
        if len(parts) != 2:
            return
        owner, repo = parts
        if (
            "." in owner
            or ":" in owner
            or ":" in repo
            or owner in GITHUB_SITE_SECTIONS
        ):
            return
        key = (owner.lower(), repo.lower())
        if key in self._seen:
            return
        self._seen.add(key)
        self.repos.append(
            {
                "provider": "github",
                "owner": owner,
                "repo": repo,
                "url": f"https://github.com/{owner}/{repo}",
            }
        )

    def handle_endtag(self, tag: str) -> None:
        if tag == "h2" and self._heading_depth > 0:
            self._heading_depth -= 1
        if tag == "article" and self._article_depth > 0:
            self._article_depth -= 1


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path, default: dict) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=f"{path.stem}-", suffix=".json.tmp", dir=str(path.parent)
    )
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, path)


@contextmanager
def file_lock(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def parse_github_trending_repos(html: str) -> list[dict[str, str]]:
    parser = TrendingRepoParser()
    parser.feed(html)
    return parser.repos


def fetch_github_trending_repos(*, since: str = "daily") -> list[dict[str, str]]:
    url = f"{GITHUB_TRENDING_URL}?since={since}"
    request = Request(
        url,
        headers={
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.5",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/91.0.4472.124 Safari/537.36"
            ),
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            html = response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        if exc.code == 429:
            raise RuntimeError("GitHub Trending request was rate limited") from exc
        raise RuntimeError(f"GitHub Trending request failed with HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"GitHub Trending request failed: {exc.reason}") from exc
    return parse_github_trending_repos(html)


def _repo_key(repo: dict) -> tuple[str, str, str]:
    return (
        str(repo.get("provider", "github")).lower(),
        str(repo.get("owner", "")).lower(),
        str(repo.get("repo", "")).lower(),
    )


def _parse_report_date(value: str) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(value[:10])
        except ValueError:
            return None


def repo_was_recently_analyzed(
    reports_index: dict,
    repo: dict,
    *,
    now_date: str,
    dedupe_days: int,
) -> bool:
    cutoff = date.fromisoformat(now_date) - timedelta(days=dedupe_days)
    target_key = _repo_key(repo)
    for report in reports_index.get("reports", []):
        if _repo_key(report) != target_key:
            continue
        analyzed = _parse_report_date(str(report.get("analyzed", "")))
        if analyzed and analyzed >= cutoff:
            return True
    return False


def build_trending_job(repo: dict, *, submitted_at: str) -> dict:
    owner = repo["owner"]
    name = repo["repo"]
    digest = hashlib.sha256(f"{owner}{name}{submitted_at}".encode()).hexdigest()[:8]
    return {
        "id": f"{owner}-{name}-{digest}",
        "url": repo["url"],
        "provider": repo.get("provider", "github"),
        "owner": owner,
        "repo": name,
        "status": "pending",
        "submitted": submitted_at,
        "source": "github_trending",
        "options": {
            "ecosystem": "auto",
            "severity": "low",
            "depth": "shallow",
        },
    }


def enqueue_trending_repos(
    queue: dict,
    reports_index: dict,
    repos: list[dict[str, str]],
    *,
    now_value: str,
    dedupe_days: int,
) -> dict:
    result = {
        "enqueued": [],
        "skipped_recent": [],
        "skipped_active": [],
    }
    now_date = now_value[:10]
    for repo in repos:
        label = f"{repo['owner']}/{repo['repo']}"
        if repo_was_recently_analyzed(
            reports_index,
            repo,
            now_date=now_date,
            dedupe_days=dedupe_days,
        ):
            result["skipped_recent"].append(label)
            continue

        job = build_trending_job(repo, submitted_at=now_value)
        try:
            enqueue_job(queue, job)
        except ValueError:
            result["skipped_active"].append(label)
            continue
        result["enqueued"].append(job["id"])
    return result


def run_once(
    *,
    since: str,
    max_repos: int,
    dedupe_days: int,
    trigger_worker: bool,
) -> dict:
    repos = fetch_github_trending_repos(since=since)[:max_repos]
    submitted_at = now()
    with reports_lock():
        reports_index = load_json(REPORTS_INDEX_FILE, {"reports": []})
    with queue_lock():
        queue = load_json(QUEUE_FILE, {"jobs": []})
        result = enqueue_trending_repos(
            queue,
            reports_index,
            repos,
            now_value=submitted_at,
            dedupe_days=dedupe_days,
        )
        queue["lastUpdated"] = now()
        save_json(QUEUE_FILE, queue)

    result["fetched"] = len(repos)
    result["dedupeDays"] = dedupe_days
    result["since"] = since
    result["workerTriggered"] = False
    result["workerError"] = ""
    if trigger_worker and result["enqueued"]:
        triggered, error = trigger_worker_for_job(
            root_dir=ROOT_DIR,
            job_id=result["enqueued"][0],
        )
        result["workerTriggered"] = triggered
        result["workerError"] = error
    return result


def queue_lock():
    return file_lock(QUEUE_LOCK_FILE)


def reports_lock():
    return file_lock(REPORTS_LOCK_FILE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Queue GitHub Trending repositories.")
    parser.add_argument("--since", choices=["daily", "weekly", "monthly"], default="daily")
    parser.add_argument("--max-repos", type=int, default=DEFAULT_MAX_REPOS)
    parser.add_argument("--dedupe-days", type=int, default=DEFAULT_DEDUPE_DAYS)
    parser.add_argument("--watch", action="store_true", help="Run repeatedly.")
    parser.add_argument("--interval-hours", type=float, default=24)
    parser.add_argument(
        "--no-trigger-worker",
        action="store_true",
        help="Only enqueue jobs; assume a worker is already watching.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    while True:
        try:
            result = run_once(
                since=args.since,
                max_repos=args.max_repos,
                dedupe_days=args.dedupe_days,
                trigger_worker=not args.no_trigger_worker,
            )
        except Exception as exc:
            print(json.dumps({"error": str(exc)}, indent=2), flush=True)
            if not args.watch:
                return 1
            time.sleep(max(args.interval_hours, 0.1) * 60 * 60)
            continue
        print(json.dumps(result, indent=2), flush=True)
        if not args.watch:
            return 0
        time.sleep(max(args.interval_hours, 0.1) * 60 * 60)


if __name__ == "__main__":
    raise SystemExit(main())
