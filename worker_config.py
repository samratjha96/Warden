from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class WorkerConfig:
    model: str
    base_url: str
    api_key: str


def load_worker_config(env: Mapping[str, str] | None = None) -> WorkerConfig:
    source = os.environ if env is None else env
    return WorkerConfig(
        model=source["WARDEN_MODEL"],
        base_url=source["OPENAI_COMPATIBLE_ENDPOINT"],
        api_key=source["NVIDIA_API_KEY"],
    )
