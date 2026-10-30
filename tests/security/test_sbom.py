from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SBOM_PY = ROOT / "scripts" / "security" / "sbom.py"
LOCK = ROOT / "build" / "locks" / "runtime.lock.txt"
EMBEDDED = "build/sbom/cui-guard.cdx.json"

ENV = {**os.environ, "SOURCE_DATE_EPOCH": "1793148053"}


def run(*args: str | Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SBOM_PY), *map(str, args)],
        check=False,
        capture_output=True,
        text=True,
        env=ENV,
        cwd=ROOT,
    )


def lock_hashes() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for m in re.finditer(
        r"^([A-Za-z0-9_.-]+)==\S+.*?(?=^\S|\Z)",
        LOCK.read_text(),
        re.MULTILINE | re.DOTALL,
    ):
        out[m.group(1).lower()] = set(
            re.findall(r"--hash=sha256:([0-9a-f]{64})", m.group(0))
        )
    return out


@pytest.fixture(scope="module")
def sbom_path(tmp_path_factory, locks) -> Path:
    out = tmp_path_factory.mktemp("sbom") / "cui-guard.cdx.json"
    r = run("build", "--out", out)
    assert r.returncode == 0, r.stderr
    return out


def test_sbom_meets_minimum_elements(sbom_path):
    assert run("check", sbom_path).returncode == 0
    bom = json.loads(sbom_path.read_text())
    expected = lock_hashes()
    assert expected
    by_name = {c["name"].lower(): c for c in bom["components"]}
    assert set(by_name) == set(expected)
    for name, hashes in expected.items():
        got = {h["content"] for h in by_name[name]["hashes"] if h["alg"] == "SHA-256"}
        assert got == hashes
    root = bom["metadata"]["component"]
    assert root["name"] == "cui-guard"
    assert root["purl"] == f"pkg:pypi/cui-guard@{root['version']}"
    assert root["licenses"][0]["license"]["id"] == "Apache-2.0"
    assert root["supplier"]["name"] == "cui-guard contributors"
    assert bom["metadata"]["timestamp"] == "2026-10-28T00:40:53Z"


def test_sbom_check_rejects_missing_hash(sbom_path, tmp_path):
    bom = json.loads(sbom_path.read_text())
    del bom["components"][0]["hashes"]
    victim = bom["components"][0]["name"]
    bad = tmp_path / "bad.cdx.json"
    bad.write_text(json.dumps(bom))
    r = run("check", bad)
    assert r.returncode == 1
    assert victim in r.stderr + r.stdout


def test_sbom_check_rejects_missing_timestamp_and_graph(sbom_path, tmp_path):
    bom = json.loads(sbom_path.read_text())
    del bom["metadata"]["timestamp"]
    del bom["dependencies"]
    bad = tmp_path / "bad.cdx.json"
    bad.write_text(json.dumps(bom))
    r = run("check", bad)
    assert r.returncode == 1
    assert "timestamp" in r.stderr
    assert "dependencies" in r.stderr


def test_sbom_has_no_dev_tools(sbom_path):
    names = {c["name"].lower() for c in json.loads(sbom_path.read_text())["components"]}
    assert not names & {"pytest", "ruff", "zizmor", "pip-audit", "cyclonedx-bom"}


def test_sbom_is_deterministic(tmp_path, locks):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    assert run("build", "--out", a).returncode == 0
    assert run("build", "--out", b).returncode == 0
    assert a.read_bytes() == b.read_bytes()


def copy_tree(dest: Path) -> Path:
    """A clean copy of the tree with no build/ directory, as a fresh clone would have."""
    shutil.copytree(
        ROOT,
        dest,
        ignore=shutil.ignore_patterns(
            ".venv",
            ".git",
            ".superpowers",
            "build",
            "__pycache__",
            ".pytest_cache",
            ".ruff_cache",
            ".hypothesis",
        ),
    )
    return dest


def uv_build(tree: Path, out: Path, *args: str) -> subprocess.CompletedProcess[str]:
    uv = shutil.which("uv") or str(ROOT / ".venv" / "bin" / "uv")
    return subprocess.run(
        [uv, "build", *args, "--out-dir", str(out)],
        check=False,
        capture_output=True,
        text=True,
        env={**ENV, "UV_PYTHON_DOWNLOADS": "never"},
        cwd=tree,
    )


def wheel_names(out: Path) -> list[str]:
    (wheel,) = out.glob("*.whl")
    with zipfile.ZipFile(wheel) as z:
        return z.namelist()


@pytest.mark.network
def test_wheel_builds_without_sbom(tmp_path):
    tree = copy_tree(tmp_path / "tree")
    assert not (tree / "build").exists()
    r = uv_build(tree, tmp_path / "out")
    assert r.returncode == 0, r.stderr
    assert not [n for n in wheel_names(tmp_path / "out") if "/sboms/" in n]


@pytest.mark.network
def test_wheel_from_sdist_embeds_sbom(tmp_path, locks):
    tree = copy_tree(tmp_path / "tree")
    shutil.copytree(locks, tree / "build" / "locks")
    sbom = tree / EMBEDDED
    r = subprocess.run(
        [
            sys.executable,
            str(tree / "scripts" / "security" / "sbom.py"),
            "build",
            "--out",
            str(sbom),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=ENV,
    )
    assert r.returncode == 0, r.stderr
    # No --wheel/--sdist flag: uv builds the sdist, then the wheel from the sdist.
    r = uv_build(tree, tmp_path / "out")
    assert r.returncode == 0, r.stderr
    names = wheel_names(tmp_path / "out")
    assert "cui_guard-0.1.0.dist-info/sboms/cui-guard.cdx.json" in names
