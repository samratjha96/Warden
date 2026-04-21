from __future__ import annotations

import os
import sys
from typing import Sequence


def build_service_command(service: str, extra_args: Sequence[str]) -> list[str]:
    python = sys.executable

    if service == "server":
        return [python, "server.py", *extra_args]

    if service == "worker":
        worker_args = list(extra_args) if extra_args else ["--watch"]
        return [python, "worker/worker.py", *worker_args]

    raise ValueError(f"Unsupported service: {service}")


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        raise SystemExit("Usage: python service_runner.py <server|worker> [args...]")

    command = build_service_command(args[0], args[1:])
    os.execvp(command[0], command)
    raise AssertionError("os.execvp should not return")


if __name__ == "__main__":
    main()
