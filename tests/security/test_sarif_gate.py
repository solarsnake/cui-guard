from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "security" / "sarif_gate.py"

# Load by path: the name "security" is already taken by this test package.
_spec = importlib.util.spec_from_file_location("cui_sarif_gate", SCRIPT)
assert _spec and _spec.loader
_gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gate)
check = _gate.check
TODAY = date(2026, 10, 29)
RULE = "py/synthetic-injection"


def sarif(results: list[dict], rules: list[dict] | None = None) -> dict:
    """A minimal synthetic SARIF 2.1.0 log with one CodeQL run."""
    rules = (
        rules
        if rules is not None
        else [{"id": RULE, "defaultConfiguration": {"level": "error"}}]
    )
    return {
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": "CodeQL", "rules": rules}}, "results": results}
        ],
    }


def result(rule: str = RULE, path: str = "src/x.py", level: str | None = None) -> dict:
    out: dict = {
        "ruleId": rule,
        "message": {"text": "synthetic"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}}}],
    }
    if level is not None:
        out["level"] = level
    return out


def entry(**over) -> dict:
    e = {
        "ruleId": RULE,
        "path": "src/x.py",
        "justification": "synthetic: input is a constant",
        "recorded": "2026-10-20",
        "review-by": "2026-12-01",
    }
    e.update(over)
    return {k: v for k, v in e.items() if v is not None}


def run(tmp_path: Path, logs: list[dict], entries: list[dict]) -> list[str]:
    paths = []
    for i, log in enumerate(logs):
        p = tmp_path / f"{i}.sarif"
        p.write_text(json.dumps(log))
        paths.append(p)
    return check(paths, {"entries": entries}, TODAY)


def test_clean_sarif_passes(tmp_path):
    assert run(tmp_path, [sarif([])], []) == []


def test_error_and_warning_results_fail_note_passes(tmp_path):
    for level in ("error", "warning"):
        found = run(tmp_path, [sarif([result(level=level)])], [])
        assert found == [f"untriaged CodeQL result {RULE} in src/x.py"], level
    assert run(tmp_path, [sarif([result(level="note")])], []) == []
    assert run(tmp_path, [sarif([result(level="none")])], []) == []


def test_missing_level_takes_the_rule_default_then_warning(tmp_path):
    assert run(tmp_path, [sarif([result()])], [])  # rule default: error
    note_rule = [{"id": RULE, "defaultConfiguration": {"level": "note"}}]
    assert run(tmp_path, [sarif([result()], note_rule)], []) == []
    assert run(
        tmp_path, [sarif([result()], [{"id": RULE}])], []
    )  # SARIF default: warning
    assert run(tmp_path, [sarif([result(rule="py/unlisted")], [])], [])


def test_triaged_result_passes_only_for_its_rule_and_path(tmp_path):
    assert run(tmp_path, [sarif([result()])], [entry()]) == []
    found = run(tmp_path, [sarif([result(path="src/y.py")])], [entry()])
    assert "untriaged CodeQL result py/synthetic-injection in src/y.py" in found


def test_stale_entry_flagged_only_when_its_rule_ran(tmp_path):
    found = run(tmp_path, [sarif([])], [entry()])
    assert found == [f"triage {RULE} src/x.py: matches no result; remove the entry"]
    # The actions-language job does not run Python rules: the entry is not judged there.
    actions = sarif([], [{"id": "actions/synthetic"}])
    assert run(tmp_path, [actions], [entry()]) == []


def test_entry_date_and_field_rules(tmp_path):
    log = [sarif([result()])]
    cases = {
        "expired": entry(recorded="2026-08-01", **{"review-by": "2026-10-01"}),
        "more than 90 days after recorded": entry(**{"review-by": "2027-03-01"}),
        "recorded date is in the future": entry(recorded="2026-11-01"),
        "missing field justification": entry(justification=None),
        "missing field review-by": entry(**{"review-by": None}),
        "invalid recorded date": entry(recorded="not-a-date"),
    }
    for needle, e in cases.items():
        found = run(tmp_path, log, [e])
        assert any(needle in f for f in found), (needle, found)


def test_unreadable_or_missing_sarif_fails_closed(tmp_path):
    bad = tmp_path / "bad.sarif"
    bad.write_text("{not json")
    found = check([bad], {"entries": []}, TODAY)
    assert found and "unusable SARIF" in found[0]
    no_runs = tmp_path / "noruns.sarif"
    no_runs.write_text(json.dumps({"version": "2.1.0"}))
    assert check([no_runs], {"entries": []}, TODAY)
    assert check([], {"entries": []}, TODAY) == [
        "no SARIF files given; nothing was analyzed"
    ]
    assert check([bad], {}, TODAY) == ["triage file has no entries list"]


def test_cli_exit_codes_and_repo_triage_file(tmp_path):
    triage = json.loads((ROOT / "security" / "codeql-triage.json").read_text())
    assert isinstance(triage["entries"], list)
    clean, dirty = tmp_path / "clean.sarif", tmp_path / "dirty.sarif"
    clean.write_text(json.dumps(sarif([])))
    dirty.write_text(json.dumps(sarif([result(rule="py/never-triaged")])))

    def cli(*paths: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "check", *map(str, paths)],
            capture_output=True,
            text=True,
            check=False,
        )

    if not triage["entries"]:
        assert cli(clean).returncode == 0
    bad = cli(dirty)
    assert bad.returncode == 1 and "py/never-triaged" in bad.stderr


def test_codeql_workflow_writes_sarif_and_runs_the_gate():
    import yaml

    doc = yaml.safe_load((ROOT / ".github/workflows/codeql.yml").read_text())
    steps = doc["jobs"]["analyze"]["steps"]
    names = [s.get("name") for s in steps]
    analyze = steps[names.index("Analyze")]
    assert analyze["with"]["output"] == "sarif-results"
    gate = steps[names.index("Analyze") + 1]
    assert (
        gate["run"].strip()
        == "python3 scripts/security/sarif_gate.py check sarif-results/*.sarif"
    )
