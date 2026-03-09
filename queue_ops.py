from __future__ import annotations


def _repo_key(job: dict) -> tuple[str, str, str]:
    provider = str(job.get("provider", "")).strip().lower()
    owner = str(job.get("owner", "")).strip().lower()
    repo = str(job.get("repo", "")).strip().lower()
    return provider, owner, repo


def enqueue_job(queue: dict, job: dict) -> None:
    """Insert a queue job while preventing duplicate repo entries."""
    target_key = _repo_key(job)
    for existing in queue.get("jobs", []):
        if _repo_key(existing) == target_key:
            raise ValueError("Duplicate queue entry")
    queue.setdefault("jobs", [])
    queue["jobs"].insert(0, job)


def remove_job(queue: dict, job_id: str) -> bool:
    """Remove a queue job by ID and return whether anything was removed."""
    jobs = queue.get("jobs", [])
    original_len = len(jobs)
    queue["jobs"] = [job for job in jobs if job.get("id") != job_id]
    return len(queue["jobs"]) != original_len
