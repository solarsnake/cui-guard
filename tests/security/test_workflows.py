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
