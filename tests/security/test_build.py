from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.network
def test_build_is_reproducible():
    r = subprocess.run(
        [str(ROOT / "scripts" / "check"), "build"],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "== build: PASS" in r.stdout
