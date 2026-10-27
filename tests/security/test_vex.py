from __future__ import annotations

import copy
import importlib.util
import json
import tomllib
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Load by path: the name "security" is already taken by this test package.
_spec = importlib.util.spec_from_file_location(
    "cui_vex", ROOT / "scripts" / "security" / "vex.py"
)
assert _spec and _spec.loader
_vex = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_vex)
ignored_ids, problems = _vex.ignored_ids, _vex.problems
TODAY = date(2026, 10, 27)


def load() -> dict:
    return json.loads((ROOT / "security" / "vex.cdx.json").read_text())


def vex_with(
    id: str = "PYSEC-2026-1",
    review_by: str = "2026-12-01",
    recorded: str = "2026-10-01",
    justification: str | None = "code_not_reachable",
) -> dict:
    vex = copy.deepcopy(load())
    analysis = {"state": "not_affected", "detail": "synthetic triage note"}
    if justification is not None:
        analysis["justification"] = justification
    vex["vulnerabilities"] = [
        {
            "id": id,
            "analysis": analysis,
            "properties": [
                {"name": "cui-guard:review-by", "value": review_by},
                {"name": "cui-guard:recorded", "value": recorded},
            ],
        }
    ]
    return vex


def test_empty_vex_has_no_problems():
    assert problems(load(), TODAY, None) == []


def test_empty_vex_is_cyclonedx_1_6():
    vex = load()
    assert vex["bomFormat"] == "CycloneDX"
    assert vex["specVersion"] == "1.6"
    assert vex["vulnerabilities"] == []


def test_valid_entry_has_no_problems_and_is_ignored():
    vex = vex_with()
    assert problems(vex, TODAY, {"PYSEC-2026-1"}) == []
    assert ignored_ids(vex) == ["PYSEC-2026-1"]


def test_expired_entry_flagged():
    found = problems(
        vex_with(review_by="2026-10-26", recorded="2026-08-01"), TODAY, None
    )
    assert "expired" in " ".join(found)


def test_review_window_over_90_days_flagged():
    found = problems(
        vex_with(review_by="2027-02-01", recorded="2026-10-27"), TODAY, None
    )
    assert "90 days" in " ".join(found)


def test_entry_matching_nothing_flagged():
    found = problems(vex_with(id="PYSEC-0000-0"), TODAY, set())
    assert "matches no finding" in " ".join(found)


def test_missing_justification_flagged():
    found = problems(vex_with(justification=None), TODAY, None)
    assert "justification" in " ".join(found)


def test_gitleaks_config_allowlists_only_test_paths():
    cfg = tomllib.loads((ROOT / ".gitleaks.toml").read_text())
    paths = cfg["allowlist"]["paths"]
    assert paths
    assert all(
        p.lstrip("^").startswith(
            ("tests/", "src/cui_guard/detect/rules/credential_patterns")
        )
        for p in paths
    )


def test_zizmor_requires_hash_pins():
    assert "hash-pin" in (ROOT / ".github/zizmor.yml").read_text()
