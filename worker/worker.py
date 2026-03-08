#!/usr/bin/env python3
"""
OSS Watchdog Worker

Watches the job queue and processes pending security analyses.
Invokes Claude CLI to run the analysis using the SOP prompt.

Usage:
    python3 worker.py              # Run once, process all pending jobs
    python3 worker.py --watch      # Watch mode, poll every 30s
    python3 worker.py --job <id>   # Process specific job by ID
"""

import json
import os
import sys
import subprocess
import shutil
from datetime import datetime, timezone
from pathlib import Path

# Paths relative to this script
SCRIPT_DIR = Path(__file__).parent.absolute()
ROOT_DIR = SCRIPT_DIR.parent
SITE_DIR = ROOT_DIR / "site"
QUEUE_FILE = SITE_DIR / "data" / "queue" / "jobs.json"
REPORTS_DIR = SITE_DIR / "data" / "reports"
REPORTS_INDEX = REPORTS_DIR / "index.json"
PROMPT_FILE = SCRIPT_DIR / "PROMPT.md"
CLONE_BASE = Path("/tmp/oss-watchdog-analysis")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_queue():
    return load_json(QUEUE_FILE) or {"jobs": []}


def save_queue(q):
    save_json(QUEUE_FILE, q)


def load_reports_index():
    return load_json(REPORTS_INDEX) or {"reports": []}


def save_reports_index(idx):
    save_json(REPORTS_INDEX, idx)


def get_pending_jobs():
    q = load_queue()
    return [j for j in q["jobs"] if j.get("status") == "pending"]


def update_job_status(job_id, status, error=None):
    q = load_queue()
    for job in q["jobs"]:
        if job["id"] == job_id:
            job["status"] = status
            if error:
                job["error"] = error
            break
    q["lastUpdated"] = now()
    save_queue(q)


def remove_job(job_id):
    q = load_queue()
    q["jobs"] = [j for j in q["jobs"] if j["id"] != job_id]
    q["lastUpdated"] = now()
    save_queue(q)


def add_report_to_index(report):
    """Add report summary to reports index."""
    idx = load_reports_index()

    # Remove existing entry if present
    idx["reports"] = [r for r in idx["reports"] if r["id"] != report["id"]]

    # Add new entry at the top
    idx["reports"].insert(
        0,
        {
            "id": report["id"],
            "owner": report["owner"],
            "repo": report["repo"],
            "commit": report.get("commit", "unknown"),
            "analyzed": report["analyzed"],
            "ecosystem": report.get("primaryEcosystem", "unknown"),
            "risk": report["risk"],
            "verdict": report["verdict"],
            "keyFinding": report["keyFinding"],
        },
    )

    idx["lastUpdated"] = now()
    save_reports_index(idx)


def build_prompt(job):
    """Build the full prompt for Claude."""
    prompt_template = PROMPT_FILE.read_text()

    job_context = f"""
## Job to Process

- **Job ID**: {job["id"]}
- **URL**: {job["url"]}
- **Owner**: {job["owner"]}
- **Repo**: {job["repo"]}
- **Options**: {json.dumps(job.get("options", {}))}

## Output Location

Write the JSON report to: `{REPORTS_DIR}/{job["id"]}.json`

Begin the security analysis now. Clone the repository, perform all analysis steps, and output the JSON report.
"""

    return prompt_template + "\n\n" + job_context


def run_analysis(job):
    """Run the security analysis using Claude CLI."""
    job_id = job["id"]
    print(f"\n{'=' * 60}")
    print(f"Processing: {job['owner']}/{job['repo']}")
    print(f"Job ID: {job_id}")
    print(f"{'=' * 60}\n")

    # Update status to processing
    update_job_status(job_id, "processing")

    # Build prompt
    prompt = build_prompt(job)

    # Create temp file for prompt
    prompt_file = CLONE_BASE / f"{job_id}-prompt.md"
    prompt_file.parent.mkdir(parents=True, exist_ok=True)
    prompt_file.write_text(prompt)

    try:
        # Run Claude CLI in print mode with permissions bypassed
        result = subprocess.run(
            [
                "claude",
                "-p",  # print mode
                "--dangerously-skip-permissions",
                "--output-format",
                "text",
                prompt,
            ],
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout
            cwd=str(ROOT_DIR),
        )

        if result.returncode != 0:
            raise Exception(f"Claude CLI failed: {result.stderr}")

        # Check if report was created
        report_path = REPORTS_DIR / f"{job_id}.json"
        if not report_path.exists():
            raise Exception("Report file was not created")

        # Load and validate report
        report = load_json(report_path)
        if not report:
            raise Exception("Report file is invalid JSON")

        # Add to index
        add_report_to_index(report)

        # Remove job from queue (success)
        remove_job(job_id)

        print(f"\n[SUCCESS] Report generated: {report_path}")
        print(f"  Verdict: {report.get('verdict', 'unknown')}")
        print(f"  Risk: {report.get('risk', 'unknown')}")
        print(f"  Key Finding: {report.get('keyFinding', 'N/A')}")

        return True

    except subprocess.TimeoutExpired:
        update_job_status(job_id, "failed", "Analysis timed out after 10 minutes")
        print(f"[FAILED] Timeout: {job_id}")
        return False

    except Exception as e:
        update_job_status(job_id, "failed", str(e))
        print(f"[FAILED] {job_id}: {e}")
        return False

    finally:
        # Cleanup prompt file
        if prompt_file.exists():
            prompt_file.unlink()

        # Cleanup clone dir
        clone_dir = CLONE_BASE / job_id
        if clone_dir.exists():
            shutil.rmtree(clone_dir, ignore_errors=True)


def process_all_pending():
    """Process all pending jobs."""
    jobs = get_pending_jobs()

    if not jobs:
        print("No pending jobs in queue")
        return

    print(f"Found {len(jobs)} pending job(s)")

    for job in jobs:
        run_analysis(job)


def process_job_by_id(job_id):
    """Process a specific job by ID."""
    q = load_queue()
    job = next((j for j in q["jobs"] if j["id"] == job_id), None)

    if not job:
        print(f"Job not found: {job_id}")
        return False

    return run_analysis(job)


def watch_mode(interval=30):
    """Watch mode - poll for new jobs periodically."""
    import time

    print(f"Watching for jobs (polling every {interval}s)...")
    print("Press Ctrl+C to stop\n")

    try:
        while True:
            jobs = get_pending_jobs()
            if jobs:
                for job in jobs:
                    run_analysis(job)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopping worker...")


def main():
    args = sys.argv[1:]

    if "--watch" in args:
        watch_mode()
    elif "--job" in args:
        idx = args.index("--job")
        if idx + 1 < len(args):
            process_job_by_id(args[idx + 1])
        else:
            print("Error: --job requires a job ID")
            sys.exit(1)
    else:
        process_all_pending()


if __name__ == "__main__":
    main()
