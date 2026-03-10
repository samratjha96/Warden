from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Callable, Sequence


def build_worker_command(root_dir: Path, job_id: str) -> list[str]:
    _ = root_dir
    return ["uv", "run", "worker/worker.py", "--job", job_id]


def _open_worker_log_file() -> object:
    tmp_dir = os.environ.get("TMPDIR", "/tmp")
    log_path = Path(tmp_dir) / "warden-worker.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    return open(log_path, "a")


def trigger_worker_for_job(
    *,
    root_dir: Path,
    job_id: str,
    spawn_fn: Callable[..., object] = subprocess.Popen,
) -> tuple[bool, str]:
    command: Sequence[str] = build_worker_command(root_dir, job_id)
    log_file = _open_worker_log_file()
    try:
        spawn_fn(
            args=list(command),
            cwd=str(root_dir),
            stdout=log_file,
            stderr=log_file,
            start_new_session=True,
        )
        return True, ""
    except Exception as exc:
        return False, str(exc)
    finally:
        log_file.close()
