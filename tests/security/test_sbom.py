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
LOCK = ROOT / "requirements" / "runtime.lock.txt"
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
def sbom_path(tmp_path_factory) -> Path:
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


def test_sbom_is_deterministic(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    assert run("build", "--out", a).returncode == 0
    assert run("build", "--out", b).returncode == 0
    assert a.read_bytes() == b.read_bytes()


@pytest.mark.network
def test_wheel_embeds_sbom(tmp_path):
    # sbom-files is resolved from the project root, so build in a copy-free way:
    # create the SBOM at its fixed path, then build the wheel.
    assert run("build", "--out", ROOT / EMBEDDED).returncode == 0
    uv = shutil.which("uv") or str(ROOT / ".venv" / "bin" / "uv")
    r = subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
        env={**ENV, "UV_PYTHON_DOWNLOADS": "never"},
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr
    (wheel,) = tmp_path.glob("*.whl")
    version = wheel.name.split("-")[1]
    with zipfile.ZipFile(wheel) as z:
        assert f"cui_guard-{version}.dist-info/sboms/cui-guard.cdx.json" in z.namelist()
