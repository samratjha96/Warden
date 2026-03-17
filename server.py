#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "python-dotenv>=1.0.0",
# ]
# ///
"""
Warden Server

Usage:
    uv run server.py [port]

Serves static files from ./site and handles POST /api/submit
"""

import json
import os
import hashlib
import re
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import fcntl

# Load .env file from project root before accessing env vars
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env")

from queue_ops import enqueue_job, remove_job
from regeneration import build_regeneration_job
from report_ops import delete_report_files, remove_report
from repo_url import parse_repo_url
from submission_limits import SubmissionLimiter
from worker_trigger import trigger_worker_for_job

PORT = int(os.environ.get("PORT", 12000))
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SITE_DIR = os.path.join(ROOT_DIR, "site")
QUEUE_FILE = os.path.join(SITE_DIR, "data", "queue", "jobs.json")
QUEUE_LOCK_FILE = QUEUE_FILE + ".lock"
REPORTS_DIR = os.path.join(SITE_DIR, "data", "reports")
REPORTS_INDEX_FILE = os.path.join(REPORTS_DIR, "index.json")
REPORTS_LOCK_FILE = REPORTS_INDEX_FILE + ".lock"
MAX_ACTIVE_JOBS = int(os.environ.get("MAX_ACTIVE_JOBS", "1"))
SUBMIT_MIN_INTERVAL_SECONDS = float(
    os.environ.get("SUBMIT_MIN_INTERVAL_SECONDS", "1.0")
)
SUBMIT_WINDOW_SECONDS = int(os.environ.get("SUBMIT_WINDOW_SECONDS", "60"))
SUBMIT_MAX_PER_WINDOW = int(os.environ.get("SUBMIT_MAX_PER_WINDOW", "30"))
SUBMISSION_LIMITER = SubmissionLimiter(
    min_interval_seconds=SUBMIT_MIN_INTERVAL_SECONDS,
    window_seconds=SUBMIT_WINDOW_SECONDS,
    max_submissions_per_window=SUBMIT_MAX_PER_WINDOW,
)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_queue():
    try:
        with open(QUEUE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"jobs": []}


def save_queue(q):
    os.makedirs(os.path.dirname(QUEUE_FILE), exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix="jobs-", suffix=".json.tmp", dir=os.path.dirname(QUEUE_FILE)
    )
    with os.fdopen(fd, "w") as f:
        json.dump(q, f, indent=2)
    os.replace(tmp_path, QUEUE_FILE)


def load_reports_index():
    try:
        with open(REPORTS_INDEX_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"reports": []}


def load_report_by_id(report_id: str):
    report_path = Path(REPORTS_DIR) / f"{report_id}.json"
    try:
        with open(report_path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_reports_index(index):
    os.makedirs(os.path.dirname(REPORTS_INDEX_FILE), exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix="reports-", suffix=".json.tmp", dir=os.path.dirname(REPORTS_INDEX_FILE)
    )
    with os.fdopen(fd, "w") as f:
        json.dump(index, f, indent=2)
    os.replace(tmp_path, REPORTS_INDEX_FILE)


def count_active_jobs(queue: dict) -> int:
    active_states = {"pending", "processing"}
    return sum(1 for job in queue.get("jobs", []) if job.get("status") in active_states)


def count_inflight_jobs(queue: dict) -> int:
    return sum(1 for job in queue.get("jobs", []) if job.get("status") == "processing")


def should_trigger_worker(*, inflight_jobs: int, max_inflight_jobs: int) -> bool:
    return inflight_jobs < max_inflight_jobs


@contextmanager
def queue_lock():
    os.makedirs(os.path.dirname(QUEUE_LOCK_FILE), exist_ok=True)
    with open(QUEUE_LOCK_FILE, "w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


@contextmanager
def reports_lock():
    os.makedirs(os.path.dirname(REPORTS_LOCK_FILE), exist_ok=True)
    with open(REPORTS_LOCK_FILE, "w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=SITE_DIR, **kw)

    def is_runtime_json_request(self):
        return self.path in {
            "/data/queue/jobs.json",
            "/data/queue/index.json",
            "/data/reports/index.json",
        } or (self.path.startswith("/data/reports/") and self.path.endswith(".json"))

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        if self.is_runtime_json_request():
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        regenerate_match = re.fullmatch(
            r"/api/reports/([a-zA-Z0-9_.-]+)/regenerate", self.path
        )
        if regenerate_match:
            report_id = regenerate_match.group(1)

            try:
                body = json.loads(
                    self.rfile.read(int(self.headers.get("Content-Length", 0)))
                )
            except Exception:
                body = {}

            report = load_report_by_id(report_id)
            if not isinstance(report, dict):
                return self.respond(
                    404,
                    {
                        "error": (
                            "No matching report found to regenerate. It may have been removed."
                        )
                    },
                )

            job = build_regeneration_job(
                report,
                steering=str(body.get("steering", "")),
                submitted_at=now(),
            )

            inflight_jobs = 0
            with queue_lock():
                q = load_queue()
                inflight_jobs = count_inflight_jobs(q)
                try:
                    enqueue_job(q, job)
                except ValueError:
                    return self.respond(
                        409,
                        {
                            "error": (
                                "Regeneration blocked: this repository already has an active "
                                "queue entry. Wait for the current mission to finish or remove it first."
                            ),
                            "code": "duplicate_queue_entry",
                        },
                    )
                q["lastUpdated"] = now()
                save_queue(q)

            print(
                f"[+] Regeneration queued: {job['owner']}/{job['repo']} ({report_id})",
                flush=True,
            )
            triggered = False
            worker_error = ""
            dispatch_code = ""
            retry_after = 0

            if not should_trigger_worker(
                inflight_jobs=inflight_jobs,
                max_inflight_jobs=MAX_ACTIVE_JOBS,
            ):
                dispatch_code = "queued_for_later_inflight_limit"
                worker_error = "Queued for later processing: in-flight worker limit currently reached."
            else:
                allowed, limit_code, limiter_retry_after = SUBMISSION_LIMITER.allow()
                if not allowed:
                    dispatch_code = limit_code
                    retry_after = limiter_retry_after
                    worker_error = "Queued for later processing: dispatch temporarily deferred by submit limiter."
                else:
                    triggered, worker_error = trigger_worker_for_job(
                        root_dir=Path(ROOT_DIR),
                        job_id=report_id,
                    )
                    if not triggered:
                        dispatch_code = "worker_trigger_failed"
                        print(
                            f"[!] Failed to auto-trigger worker for regeneration {report_id}: {worker_error}",
                            flush=True,
                        )

            if triggered:
                dispatch_code = "triggered"
            if not triggered and not worker_error:
                worker_error = "Queued for later processing."

            return self.respond(
                201,
                {
                    "job": job,
                    "autoWorkerTriggered": triggered,
                    "workerError": worker_error,
                    "queuedForLater": not triggered,
                    "dispatchCode": dispatch_code,
                    "retryAfterSeconds": retry_after,
                    "regeneratedReportId": report_id,
                },
                headers={"Retry-After": str(retry_after)} if retry_after > 0 else None,
            )

        if self.path != "/api/submit":
            return self.send_error(404)

        try:
            body = json.loads(
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
            )
        except Exception:
            return self.respond(400, {"error": "Invalid JSON"})

        try:
            parsed = parse_repo_url(body.get("url", ""))
        except ValueError:
            return self.respond(400, {"error": "Invalid repo URL"})

        url = parsed["url"]
        owner = parsed["owner"]
        repo = parsed["repo"]
        provider = parsed["provider"]
        job_id = f"{owner}-{repo}-{hashlib.sha256(f'{owner}{repo}{now()}'.encode()).hexdigest()[:8]}"

        job = {
            "id": job_id,
            "url": url,
            "provider": provider,
            "owner": owner,
            "repo": repo,
            "status": "pending",
            "submitted": now(),
            "options": {
                "ecosystem": body.get("ecosystem", "auto"),
                "severity": body.get("severity", "low"),
                "depth": body.get("depth", "shallow"),
            },
        }

        inflight_jobs = 0
        with queue_lock():
            q = load_queue()
            inflight_jobs = count_inflight_jobs(q)
            try:
                enqueue_job(q, job)
            except ValueError:
                return self.respond(
                    409,
                    {
                        "error": (
                            "Duplicate blocked: this repository is already in the queue. "
                            "Stand down and monitor the existing mission."
                        ),
                        "code": "duplicate_queue_entry",
                    },
                )
            q["lastUpdated"] = now()
            save_queue(q)

        print(f"[+] Queued: {owner}/{repo} ({job_id})", flush=True)
        triggered = False
        worker_error = ""
        dispatch_code = ""
        retry_after = 0

        if not should_trigger_worker(
            inflight_jobs=inflight_jobs,
            max_inflight_jobs=MAX_ACTIVE_JOBS,
        ):
            dispatch_code = "queued_for_later_inflight_limit"
            worker_error = (
                "Queued for later processing: in-flight worker limit currently reached."
            )
        else:
            allowed, limit_code, limiter_retry_after = SUBMISSION_LIMITER.allow()
            if not allowed:
                dispatch_code = limit_code
                retry_after = limiter_retry_after
                worker_error = "Queued for later processing: dispatch temporarily deferred by submit limiter."
            else:
                triggered, worker_error = trigger_worker_for_job(
                    root_dir=Path(ROOT_DIR),
                    job_id=job_id,
                )
                if not triggered:
                    dispatch_code = "worker_trigger_failed"
                    print(
                        f"[!] Failed to auto-trigger worker for {job_id}: {worker_error}",
                        flush=True,
                    )

        if triggered:
            dispatch_code = "triggered"
        if not triggered and not worker_error:
            worker_error = "Queued for later processing."
        if not triggered:
            print(
                f"[i] Job queued without immediate trigger: {job_id} ({worker_error})",
                flush=True,
            )

        self.respond(
            201,
            {
                "job": job,
                "autoWorkerTriggered": triggered,
                "workerError": worker_error,
                "queuedForLater": not triggered,
                "dispatchCode": dispatch_code,
                "retryAfterSeconds": retry_after,
            },
            headers={"Retry-After": str(retry_after)} if retry_after > 0 else None,
        )
        return

    def do_DELETE(self):
        queue_match = re.fullmatch(r"/api/queue/([a-zA-Z0-9_.-]+)", self.path)
        if queue_match:
            job_id = queue_match.group(1)
            with queue_lock():
                q = load_queue()
                removed = remove_job(q, job_id)
                if not removed:
                    return self.respond(
                        404,
                        {
                            "error": (
                                "No matching mission in queue. It may have already completed "
                                "or been removed."
                            )
                        },
                    )
                q["lastUpdated"] = now()
                save_queue(q)
            return self.respond(200, {"ok": True, "jobId": job_id})

        report_match = re.fullmatch(r"/api/reports/([a-zA-Z0-9_.-]+)", self.path)
        if report_match:
            report_id = report_match.group(1)
            with reports_lock():
                index = load_reports_index()
                removed_from_index = remove_report(index, report_id)
                removed_files = delete_report_files(Path(REPORTS_DIR), report_id)
                if not removed_from_index and not removed_files:
                    return self.respond(
                        404,
                        {
                            "error": (
                                "No matching report found. It may have already been removed."
                            )
                        },
                    )
                index["lastUpdated"] = now()
                save_reports_index(index)
            return self.respond(
                200,
                {
                    "ok": True,
                    "reportId": report_id,
                    "removedFiles": [Path(path).name for path in removed_files],
                },
            )

        return self.send_error(404)

    def respond(self, status, data, headers=None):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    print(f"http://localhost:{port}", flush=True)
    HTTPServer(("", port), Handler).serve_forever()
