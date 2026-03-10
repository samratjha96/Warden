from __future__ import annotations

from typing import Callable


def run_target_then_drain(
    *,
    job: dict | None,
    run_target: Callable[[dict], bool],
    drain_backlog: Callable[[], None],
) -> bool:
    if job is None:
        drain_backlog()
        return False

    result = bool(run_target(job))
    drain_backlog()
    return result
