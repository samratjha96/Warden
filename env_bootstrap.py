from __future__ import annotations

import importlib
from pathlib import Path


def load_project_dotenv(path: Path) -> bool:
    try:
        dotenv = importlib.import_module("dotenv")
    except ModuleNotFoundError:
        return False

    dotenv.load_dotenv(path)
    return True
