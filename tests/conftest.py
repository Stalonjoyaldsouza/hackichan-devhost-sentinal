from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from sentinel.runtime import DEFAULT_POLICY, Runtime


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    p = tmp_path / "policy.yaml"
    shutil.copy(DEFAULT_POLICY, p)
    return p


@pytest.fixture
def rt(tmp_path: Path, policy_path: Path) -> Iterator[Runtime]:
    runtime = Runtime.build(tmp_path / "audit.db", policy_path)
    yield runtime
    runtime.close()


@pytest.fixture
def secops(rt: Runtime) -> str:
    return rt.human("human.secops")
