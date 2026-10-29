from __future__ import annotations

import importlib.util
import json
import os
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


def copy_fixture(raw: Path) -> Path:
    """The raw fixture plus the fips gate's status (Docker present, provider checks passed)."""
    shutil.copytree(FIXTURE, raw)
    (raw / "fips.status").write_text("PASS 40\n")
    return raw


def render(
    raw: Path, out: Path, strict: bool = False
) -> subprocess.CompletedProcess[str]:
    # The mode is set per test: CI's security job runs this suite with CUI_GUARD_STRICT=1.
    env = {k: v for k, v in os.environ.items() if k != "CUI_GUARD_STRICT"}
    if strict:
        env["CUI_GUARD_STRICT"] = "1"
    return subprocess.run(
        [sys.executable, str(SCRIPT), "render", "--raw", str(raw), "--out", str(out)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_report_renders_from_raw_fixture(tmp_path):
    out = tmp_path / "out"
    done = render(copy_fixture(tmp_path / "raw"), out)
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
    copy_fixture(raw)
    text = " ".join(CANARIES.values())
    (raw / "test.xml").write_text(
        '<?xml version="1.0"?><testsuites><testsuite tests="1" failures="1">'
        f'<testcase classname="t" name="test_{text}"><failure message="{text}">'
        f"{text}</failure></testcase></testsuite></testsuites>"
    )
    (raw / "test.status").write_text(f"FAIL 1 {text}\n")
    # An audit advisory description and a SKIPPED reason carrying canaries.
    (raw / "audit-dev-pypi.json").write_text(
        json.dumps(
            {
                "dependencies": [
                    {
                        "name": "examplepkg",
                        "version": "1.0.0",
                        "vulns": [{"id": "PYSEC-2026-1", "description": text}],
                    }
                ]
            }
        )
    )
    (raw / "secrets.status").write_text(f"SKIPPED 0 {text}\n")
    out = tmp_path / "out"
    assert render(raw, out).returncode == 1
    # Proves the junit was parsed, not skipped.
    assert json.loads((out / "report.json").read_text())["tests"]["test"]["failed"] == 1
    for name in ("summary.md", "report.json"):
        body = (out / name).read_text()
        for canary in CANARIES.values():
            assert canary not in body


def test_report_exit_code_reflects_failures(tmp_path):
    raw = tmp_path / "raw"
    copy_fixture(raw)
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


def run_case(tmp_path, mutate):
    raw = tmp_path / "raw"
    copy_fixture(raw)
    mutate(raw)
    out = tmp_path / "out"
    done = render(raw, out)
    assert (out / "report.json").exists() and (out / "summary.md").exists()
    return (
        done,
        json.loads((out / "report.json").read_text()),
        (out / "summary.md").read_text(),
    )


def test_pass_gate_with_missing_junit_fails(tmp_path):
    done, report, _ = run_case(tmp_path, lambda raw: (raw / "leak.xml").unlink())
    assert done.returncode == 1
    assert report["gates"]["leak"]["status"] == "FAIL"


def test_pass_gate_with_junit_failures_fails(tmp_path):
    def mutate(raw):
        xml = (
            (raw / "fuzz.xml")
            .read_text()
            .replace(
                '<testcase classname="tests.fuzz" name="test_p"/>',
                '<testcase classname="tests.fuzz" name="test_p"><failure message="m"/></testcase>',
            )
        )
        (raw / "fuzz.xml").write_text(xml)

    done, report, _ = run_case(tmp_path, mutate)
    assert done.returncode == 1
    assert report["tests"]["fuzz"]["failed"] == 1
    assert report["gates"]["fuzz"]["status"] == "FAIL"


def test_unreadable_audit_json_fails(tmp_path):
    done, report, summary = run_case(
        tmp_path, lambda raw: (raw / "audit-runtime-osv.json").write_text("not json")
    )
    assert done.returncode == 1
    assert report["unreadable_audit_results"] == 1
    assert "audit results missing or unreadable" in summary


def test_unsafe_finding_id_is_counted_not_dropped_silently(tmp_path):
    def mutate(raw):
        data = json.loads((raw / "audit-dev-pypi.json").read_text())
        data["dependencies"][0]["vulns"][0]["id"] = "bad id with spaces"
        (raw / "audit-dev-pypi.json").write_text(json.dumps(data))

    done, report, summary = run_case(tmp_path, mutate)
    assert done.returncode == 1
    assert report["omitted_findings"] == 1
    assert "1 findings omitted" in summary
    assert "bad id" not in summary


def test_section_exception_still_writes_report(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("cui_report_mod", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def boom():
        raise RuntimeError("secret detail")

    monkeypatch.setattr(mod, "known_gaps", boom)
    out = tmp_path / "out"
    raw = copy_fixture(tmp_path / "raw")
    monkeypatch.setattr(
        sys, "argv", ["report.py", "render", "--raw", str(raw), "--out", str(out)]
    )
    assert mod.main() == 1
    report = json.loads((out / "report.json").read_text())
    assert report["errors"] == ["known gaps: failed to build"]
    assert "secret detail" not in (out / "summary.md").read_text()


def test_missing_sbom_digest_fails(tmp_path):
    done, report, _ = run_case(tmp_path, lambda raw: (raw / "sbom.sha256").unlink())
    assert done.returncode == 1
    assert report["sbom_sha256"] is None


def test_non_reproducible_build_fails(tmp_path):
    def mutate(raw):
        (raw / "build-b.digests").write_text(
            "c" * 64 + "  cui_guard-0.0.0-py3-none-any.whl\n"
        )

    done, report, _ = run_case(tmp_path, mutate)
    assert done.returncode == 1
    assert report["build_digests"]["reproducible"] is False


def test_summary_lists_skipped_gates(tmp_path):
    done, _, summary = run_case(tmp_path, lambda raw: None)
    assert done.returncode == 0
    assert "Overall: PASS (2 skipped: secrets, workflows)" in summary


def test_fips_gate_reported_with_docker_skip_reason(tmp_path):
    done, report, summary = run_case(
        tmp_path, lambda raw: (raw / "fips.status").write_text("SKIPPED 0 docker not available\n")
    )
    assert done.returncode == 0
    assert report["gates"]["fips"] == {"status": "SKIPPED", "seconds": 0, "reason": "docker not available"}
    assert "Overall: PASS (3 skipped: secrets, workflows, fips)" in summary


def test_missing_fips_status_fails(tmp_path):
    done, report, _ = run_case(tmp_path, lambda raw: (raw / "fips.status").unlink())
    assert done.returncode == 1
    assert report["gates"]["fips"]["status"] == "MISSING"


def test_strict_mode_fails_on_a_skipped_gate(tmp_path):
    raw = copy_fixture(
        tmp_path / "raw"
    )  # secrets and workflows are SKIPPED in the fixture
    out = tmp_path / "out"
    done = render(raw, out, strict=True)
    assert done.returncode == 1
    report = json.loads((out / "report.json").read_text())
    assert report["ok"] is False and report["strict"] is True
    assert report["gates"]["secrets"]["status"] == "SKIPPED"
    summary = (out / "summary.md").read_text()
    assert "Overall: FAIL (2 skipped: secrets, workflows)" in summary
    assert "Mode: strict" in summary
    assert "gate secrets: SKIPPED" in done.stderr


def test_strict_mode_passes_when_every_gate_ran(tmp_path):
    raw = copy_fixture(tmp_path / "raw")
    for gate in ("secrets", "workflows"):
        (raw / f"{gate}.status").write_text("PASS 1\n")
    done = render(raw, tmp_path / "out", strict=True)
    assert done.returncode == 0, done.stderr
    assert render(raw, tmp_path / "local").returncode == 0


def test_local_mode_is_the_default(tmp_path):
    done = render(copy_fixture(tmp_path / "raw"), tmp_path / "out")
    assert done.returncode == 0
    report = json.loads((tmp_path / "out" / "report.json").read_text())
    assert report["strict"] is False


def _check(gate: str, root: Path, strict: bool) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "CUI_GUARD_STRICT"}
    env["CUI_GUARD_ROOT"] = str(root)  # no .github/workflows here: the gate skips
    if strict:
        env["CUI_GUARD_STRICT"] = "1"
    return subprocess.run(
        [str(ROOT / "scripts" / "check"), gate],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_check_strict_mode_turns_a_skip_into_a_failure(tmp_path):
    local = _check("workflows", tmp_path, strict=False)
    assert local.returncode == 0 and "== workflows: SKIPPED" in local.stdout
    strict = _check("workflows", tmp_path, strict=True)
    assert strict.returncode == 1
    assert "== workflows: FAIL (skipped in strict mode: no workflows yet)" in strict.stdout
