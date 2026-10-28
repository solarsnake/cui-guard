from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / "fixtures" / "report_raw"
SCRIPT = ROOT / "scripts" / "security" / "report.py"

# Load by path (the name "security" is taken by this test package) to reach the canaries.
_spec = importlib.util.spec_from_file_location(
    "cui_canaries", ROOT / "tests" / "leak" / "canaries.py"
)
assert _spec and _spec.loader
_canaries = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_canaries)
CANARIES = _canaries.CANARIES


def render(raw: Path, out: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "render", "--raw", str(raw), "--out", str(out)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_report_renders_from_raw_fixture(tmp_path):
    out = tmp_path / "out"
    done = render(FIXTURE, out)
    assert done.returncode == 0, done.stderr
    summary = (out / "summary.md").read_text()
    assert "| Gate | Status |" in summary
    assert "| leak | PASS" in summary
    assert "| secrets | SKIPPED" in summary
    report = json.loads((out / "report.json").read_text())
    for key in (
        "commit",
        "date",
        "tools",
        "gates",
        "tests",
        "dependency_findings",
        "known_gaps",
        "sbom_sha256",
        "build_digests",
    ):
        assert key in report
    assert report["tests"]["leak"] == {
        "passed": 1,
        "failed": 0,
        "xfailed": 2,
        "skipped": 0,
    }
    assert report["tests"]["test"]["skipped"] == 1
    assert report["sbom_sha256"] == "a" * 64
    assert report["build_digests"]["reproducible"] is True
    finding = report["dependency_findings"][0]
    assert finding["id"] == "PYSEC-2026-1"
    assert finding["package"] == "examplepkg"
    assert finding["vex"] == "untriaged"
    assert "synthetic advisory text" not in json.dumps(report) + summary
    assert report["known_gaps"]
    assert all("/" in gap for gap in report["known_gaps"])


def test_report_contains_no_canaries(tmp_path):
    raw = tmp_path / "raw"
    shutil.copytree(FIXTURE, raw)
    text = " ".join(CANARIES.values())
    (raw / "test.xml").write_text(
        '<?xml version="1.0"?><testsuites><testsuite tests="1" failures="1">'
        f'<testcase classname="t" name="test_{text}"><failure message="{text}">'
        f"{text}</failure></testcase></testsuite></testsuites>"
    )
    (raw / "test.status").write_text(f"FAIL 1 {text}\n")
    out = tmp_path / "out"
    assert render(raw, out).returncode == 1
    for name in ("summary.md", "report.json"):
        body = (out / name).read_text()
        for canary in CANARIES.values():
            assert canary not in body


def test_report_exit_code_reflects_failures(tmp_path):
    raw = tmp_path / "raw"
    shutil.copytree(FIXTURE, raw)
    assert render(raw, tmp_path / "ok").returncode == 0
    (raw / "lint.status").write_text("FAIL 2\n")
    out = tmp_path / "bad"
    assert render(raw, out).returncode == 1
    assert (out / "summary.md").exists() and (out / "report.json").exists()
    assert (
        json.loads((out / "report.json").read_text())["gates"]["lint"]["status"]
        == "FAIL"
    )
    # A gate that never reported is a failure too.
    (raw / "lint.status").write_text("PASS 2\n")
    (raw / "build.status").unlink()
    assert render(raw, tmp_path / "missing").returncode == 1
