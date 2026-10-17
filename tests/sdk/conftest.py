from __future__ import annotations

import shutil
from pathlib import Path

import pytest

EXAMPLE = Path(__file__).resolve().parents[2] / "examples"


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A fresh copy of the example business project (with a secret-looking .env fixture)."""
    dest = tmp_path / "support_bot"
    shutil.copytree(EXAMPLE / "support_bot", dest, ignore=shutil.ignore_patterns(".sentinel", "__pycache__"))
    (dest / ".env").write_text("PAYMENTS_API_KEY=sk-live-do-not-read-0123456789abcdef\n")
    return dest


@pytest.fixture
def guidelines() -> Path:
    return EXAMPLE / "guidelines"
