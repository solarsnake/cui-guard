from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WF = sorted((ROOT / ".github/workflows").glob("*.yml"))


def test_all_five_workflows_exist():
    assert [p.name for p in WF] == ["ci.yml", "codeql.yml", "nightly.yml", "release.yml", "scorecard.yml"]


@pytest.mark.parametrize("path", WF, ids=lambda p: p.name)
def test_workflow_hardening(path):
    doc = yaml.safe_load(path.read_text())
    assert doc.get("permissions") == {}
    # PyYAML reads the bare key `on` as boolean True.
    assert "pull_request_target" not in (doc.get(True) or doc.get("on"))
    for job in doc["jobs"].values():
        for step in job.get("steps", []):
            if "uses" in step:
                assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", step["uses"]), step["uses"]
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False
            assert "${{" not in step.get("run", ""), step.get("name")


@pytest.mark.parametrize("path", WF, ids=lambda p: p.name)
def test_every_uses_has_a_version_comment(path):
    for line in path.read_text().splitlines():
        if re.match(r"\s*(-\s+)?uses:", line):
            assert re.search(r"@[0-9a-f]{40}\s+# v\d+\.\d+\.\d+$", line), line


def test_release_has_no_cache_and_publish_uses_environment():
    doc = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    for job in doc["jobs"].values():
        for step in job["steps"]:
            assert not step.get("uses", "").startswith("actions/cache@")
            if step.get("uses", "").startswith("astral-sh/setup-uv@"):
                assert step["with"]["enable-cache"] is False
    jobs = doc["jobs"]
    assert jobs["publish"]["environment"] == "release"
    assert jobs["publish"]["permissions"] == {"id-token": "write"}
    assert jobs["build"]["permissions"] == {"contents": "read"}
    assert jobs["attest"]["needs"] == "build"
    assert jobs["publish"]["needs"] == "attest"
    assert jobs["github-release"]["needs"] == "publish"
    publish = [s for s in jobs["publish"]["steps"] if s.get("uses", "").startswith("pypa/gh-action-pypi-publish@")]
    assert publish
    assert "password" not in publish[0].get("with", {})


def test_security_events_write_only_on_codeql_analyze():
    doc = yaml.safe_load((ROOT / ".github/workflows/codeql.yml").read_text())
    for name, job in doc["jobs"].items():
        assert (job["permissions"].get("security-events") == "write") == (name == "analyze")


def test_dependabot_cooldown():
    doc = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    updates = {u["package-ecosystem"]: u for u in doc["updates"]}
    assert set(updates) == {"uv", "github-actions"}
    for u in updates.values():
        assert u["cooldown"]["default-days"] == 7
        assert u["directory"] == "/"
        assert u["schedule"]["interval"] == "weekly"
    assert set(updates["uv"]["groups"]) and "minor" in str(updates["uv"]["groups"])


def _wf(name: str) -> dict:
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


def _runs(job: dict) -> list[str]:
    return [s.get("run", "") for s in job["steps"]]


def _gitleaks_install(job: dict) -> str:
    return next(r for r in _runs(job) if "gitleaks" in r and "sha256sum --check --strict" in r)


def test_ci_security_job_is_strict_and_keeps_the_report_on_failure():
    job = _wf("ci.yml")["jobs"]["security"]
    assert job["env"]["CUI_GUARD_STRICT"] == "1"
    assert "scripts/check report" in _runs(job)
    check = (ROOT / "scripts" / "check").read_text()
    assert "for g in lint lock test perf leak fuzz" in check  # report runs perf
    after = job["steps"][_runs(job).index("scripts/check report") + 1 :]
    assert after and all(s.get("if") == "${{ !cancelled() }}" for s in after)
    checkout = job["steps"][0]
    assert checkout["with"]["fetch-depth"] == 0


def test_ci_matrix_runs_no_perf_tests():
    job = _wf("ci.yml")["jobs"]["test"]
    gates = next(r for r in _runs(job) if r.startswith("scripts/check"))
    assert "test" in gates.split() and "perf" not in gates.split()
    check = (ROOT / "scripts" / "check").read_text()
    assert 'gate_test() { (cd "$ROOT" && "$(tool pytest)" -q -m "not perf"' in check
    assert 'gate_perf() { (cd "$ROOT" && "$(tool pytest)" -q -m perf $(junit perf)); }' in check
    assert "for g in lint test perf lock audit secrets workflows sbom build; do" in check


def test_release_runs_strict_report_with_gitleaks_and_full_history():
    ci, rel = _wf("ci.yml")["jobs"]["security"], _wf("release.yml")["jobs"]["build"]
    assert rel["env"]["CUI_GUARD_STRICT"] == "1"
    for key in ("GITLEAKS_VERSION", "GITLEAKS_SHA256"):
        assert rel["env"][key] == ci["env"][key]
    assert _gitleaks_install(rel) == _gitleaks_install(ci)
    assert rel["steps"][0]["with"]["fetch-depth"] == 0
    assert any(r.rstrip().endswith("scripts/check report") for r in _runs(rel))
    for step in rel["steps"]:
        if step.get("name") in ("Add report to the job summary", "Upload security report"):
            assert step["if"] == "${{ !cancelled() }}"


def test_every_release_asset_is_a_provenance_subject():
    jobs = _wf("release.yml")["jobs"]
    steps = {s.get("name"): s for s in jobs["attest"]["steps"]}
    subjects = set(steps["Attest build provenance"]["with"]["subject-path"].split())
    assert subjects == {
        "files/build/dist-a/*",
        "files/build/sbom/cui-guard.cdx.json",
        "files/security/vex.cdx.json",
        "files/requirements/runtime.lock.txt",
        "files/build/security-report/summary.md",
        "files/build/security-report/report.json",
    }
    create = next(r for r in _runs(jobs["github-release"]) if "gh release create" in r)
    for asset in re.findall(r"files/\S+", create):
        assert asset in subjects or asset == "files/build/sbom/*", asset
    assurance = (ROOT / "docs" / "SECURITY-ASSURANCE.md").read_text()
    assert "gh attestation verify runtime.lock.txt --repo <owner>/cui-guard" in assurance
