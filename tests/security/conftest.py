from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def locks() -> Path:
    """Export the hash-pinned requirements from uv.lock into build/locks (as scripts/check does)."""
    uv = ROOT / ".venv" / "bin" / "uv"
    exe = str(uv) if uv.exists() else (shutil.which("uv") or "uv")
    out = ROOT / "build" / "locks"
    out.mkdir(parents=True, exist_ok=True)
    for args, name in (
        (["--no-dev"], "runtime.lock.txt"),
        (["--only-group", "dev"], "dev.lock.txt"),
    ):
        subprocess.run(
            [exe, "export", "--frozen", *args, "--no-emit-project",
             "--format", "requirements-txt", "-o", str(out / name)],
            cwd=ROOT, check=True, capture_output=True,
        )  # fmt: skip
    return out
