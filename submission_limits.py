from __future__ import annotations

from collections import deque
from math import ceil
from threading import Lock
from time import monotonic


class SubmissionLimiter:
    """Process-local submit limiter with debounce and windowed rate limiting."""

    def __init__(
        self,
        *,
        min_interval_seconds: float,
        window_seconds: int,
        max_submissions_per_window: int,
    ) -> None:
        self.min_interval_seconds = max(0.0, float(min_interval_seconds))
        self.window_seconds = max(1, int(window_seconds))
        self.max_submissions_per_window = max(1, int(max_submissions_per_window))
        self._submission_times: deque[float] = deque()
        self._last_submission_time: float | None = None
        self._lock = Lock()

    def allow(self, now: float | None = None) -> tuple[bool, str, int]:
        timestamp = monotonic() if now is None else float(now)
        with self._lock:
            if self._last_submission_time is not None:
                elapsed = timestamp - self._last_submission_time
                if elapsed < self.min_interval_seconds:
                    retry_after = max(1, ceil(self.min_interval_seconds - elapsed))
                    return False, "submit_debounced", retry_after

            cutoff = timestamp - self.window_seconds
            while self._submission_times and self._submission_times[0] <= cutoff:
                self._submission_times.popleft()

            if len(self._submission_times) >= self.max_submissions_per_window:
                retry_after = max(1, ceil(self._submission_times[0] + self.window_seconds - timestamp))
                return False, "submit_rate_limited", retry_after

            self._submission_times.append(timestamp)
            self._last_submission_time = timestamp
            return True, "", 0
