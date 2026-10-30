from __future__ import annotations

import os
import re
import shutil
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@dataclass
class Req:
    name: str
    hashes: list[str] = field(default_factory=list)


def parse_requirements(path: Path) -> list[Req]:
    """Parse a `uv export` requirements file: one Req per pinned package."""
    reqs: list[Req] = []
    for line in path.read_text().splitlines():
        line = line.strip().rstrip("\\").strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--hash=sha256:"):
            reqs[-1].hashes.append(line.split("=", 1)[1])
            continue
        m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?==", line)
        if m:
            reqs.append(Req(re.sub(r"[-_.]+", "-", m.group(1)).lower()))
    return reqs


def documented_packages(path: Path) -> set[str]:
    """Package names in the first column of the markdown table."""
    names: set[str] = set()
    for line in path.read_text().splitlines():
        if not line.startswith("|"):
            continue
        cell = line.strip("|").split("|")[0].strip().strip("`").lower()
        if cell and cell != "package" and not set(cell) <= set("-: "):
            names.add(re.sub(r"[-_.]+", "-", cell))
    return names


def test_every_locked_requirement_has_a_hash(locks):
    for name in ("runtime.lock.txt", "dev.lock.txt"):
        reqs = parse_requirements(locks / name)
        assert reqs, name
        assert all(r.hashes for r in reqs), [r.name for r in reqs if not r.hashes]


def test_runtime_closure_is_documented(locks):
    names = {r.name for r in parse_requirements(locks / "runtime.lock.txt")}
    assert {"starlette", "uvicorn", "httpx"} <= names
    documented = documented_packages(ROOT / "DEPENDENCIES.md")
    assert names == documented, names ^ documented


def test_direct_runtime_dependencies_are_exactly_three():
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"][
        "dependencies"
    ]
    assert sorted(re.split(r"[<>=!~ ;\[]", d)[0] for d in deps) == [
        "httpx",
        "starlette",
        "uvicorn",
    ]


def test_cooldown_configured():
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert cfg["tool"]["uv"]["exclude-newer"] == "7 days"


@pytest.mark.network
def test_lock_gate_fails_on_drift(tmp_path):
    shutil.copy(ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    shutil.copy(ROOT / "uv.lock", tmp_path / "uv.lock")
    shutil.copy(ROOT / "README.md", tmp_path / "README.md")
    (tmp_path / "src").mkdir()
    shutil.copytree(ROOT / "src" / "cui_guard", tmp_path / "src" / "cui_guard")
    pp = tmp_path / "pyproject.toml"
    pp.write_text(
        pp.read_text().replace('"httpx>=0.27",', '"httpx>=0.27",\n    "idna>=3",', 1)
    )
    env = {**os.environ, "CUI_GUARD_ROOT": str(tmp_path)}
    r = subprocess.run(
        [str(ROOT / "scripts/check"), "lock"],
        check=False,
        env=env,
        capture_output=True,
        text=True,
    )
    assert r.returncode != 0
    assert "uv lock" in r.stdout + r.stderr
