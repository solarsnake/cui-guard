"""CodeQL gate: fail on any SARIF result of level error or warning not triaged in the repo.

Usage: sarif_gate.py check SARIF...   exit 1 on an untriaged result, an unreadable SARIF file,
                                      or a bad triage entry (see below)

Triage lives in security/codeql-triage.json, reviewed like the VEX:
    {"entries": [{"ruleId": "py/...", "path": "src/...", "justification": "...",
                  "recorded": "YYYY-MM-DD", "review-by": "YYYY-MM-DD"}]}
An entry needs every field, a recorded date that is not in the future, and a review-by date
that has not passed and is at most 90 days after recorded (vex.py's rules). An entry whose
rule ran in the given SARIF but matched no result is stale and must be removed. Dismissing an
alert in the GitHub UI does not count: only this file triages a result.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRIAGE_PATH = HERE.parents[1] / "security" / "codeql-triage.json"
GATED_LEVELS = {"error", "warning"}
FIELDS = ("ruleId", "path", "justification", "recorded", "review-by")


def _vex():
    # Load by path: scripts/ is not an importable package.
    spec = importlib.util.spec_from_file_location("cui_vex", HERE / "vex.py")
    if not (spec and spec.loader):
        raise ImportError("vex.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


VEX = _vex()


def _rule_levels(run: dict) -> dict[str, str]:
    """Default level per rule ID, from the driver and every extension."""
    tool = run.get("tool") or {}
    components = [tool.get("driver") or {}, *(tool.get("extensions") or [])]
    out: dict[str, str] = {}
    for comp in components:
        for rule in comp.get("rules") or []:
            level = (rule.get("defaultConfiguration") or {}).get("level", "warning")
            out[rule["id"]] = level
    return out


def results(sarif: dict) -> tuple[list[tuple[str, str]], set[str]]:
    """(ruleId, path) of every gated result, and the IDs of every rule that ran.

    A result with no level takes its rule's default, and SARIF's own default is warning,
    so a result is only ungated when it says `note` or `none`. Raises on a malformed file.
    """
    gated: list[tuple[str, str]] = []
    ran: set[str] = set()
    runs = sarif["runs"]
    if not isinstance(runs, list):
        raise TypeError("runs is not a list")
    for run in runs:
        levels = _rule_levels(run)
        ran |= set(levels)
        for res in run.get("results") or []:
            rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id")
            if not isinstance(rule_id, str):
                raise TypeError("result without a ruleId")
            ran.add(rule_id)
            level = res.get("level") or levels.get(rule_id, "warning")
            if level not in GATED_LEVELS:
                continue
            locs = res.get("locations") or [{}]
            uri = (
                (locs[0].get("physicalLocation") or {}).get("artifactLocation") or {}
            ).get("uri", "")
            gated.append((rule_id, uri))
    return gated, ran


def entry_problems(entries: list, today: date) -> list[str]:
    out: list[str] = []
    for n, e in enumerate(entries):
        name = f"triage[{n}]"
        if not isinstance(e, dict):
            out.append(f"{name}: not an object")
            continue
        name = f"{name} {e.get('ruleId')} {e.get('path')}"
        for field in FIELDS:
            if not isinstance(e.get(field), str) or not e[field]:
                out.append(f"{name}: missing field {field}")
        recorded, review_by = (
            VEX._date(e.get("recorded")),
            VEX._date(e.get("review-by")),
        )
        if e.get("recorded") and recorded is None:
            out.append(f"{name}: invalid recorded date")
        if e.get("review-by") and review_by is None:
            out.append(f"{name}: invalid review-by date")
        if recorded is not None and recorded > today:
            out.append(f"{name}: recorded date is in the future")
        if review_by is not None and review_by < today:
            out.append(f"{name}: review-by {review_by} expired (today is {today})")
        if (
            recorded is not None
            and review_by is not None
            and review_by > recorded + timedelta(days=VEX.MAX_DAYS)
        ):
            out.append(
                f"{name}: review-by {review_by} is more than {VEX.MAX_DAYS} days after recorded {recorded}"
            )
    return out


def check(sarif_paths: list[Path], triage: dict, today: date) -> list[str]:
    found: list[str] = []
    entries = triage.get("entries") if isinstance(triage, dict) else None
    if not isinstance(entries, list):
        return ["triage file has no entries list"]
    found += entry_problems(entries, today)
    triaged = {(e.get("ruleId"), e.get("path")) for e in entries if isinstance(e, dict)}
    if not sarif_paths:
        found.append("no SARIF files given; nothing was analyzed")
    gated: list[tuple[str, str]] = []
    ran: set[str] = set()
    for path in sarif_paths:
        try:
            g, r = results(json.loads(path.read_text()))
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
            IndexError,
        ) as exc:
            found.append(
                f"{path.name}: unusable SARIF, analysis incomplete ({type(exc).__name__})"
            )
            continue
        gated += g
        ran |= r
    for rule_id, uri in sorted(set(gated)):
        if (rule_id, uri) not in triaged:
            found.append(
                f"untriaged CodeQL result {rule_id} in {uri or '<no location>'}"
            )
    hits = set(gated)
    for rule_id, uri in sorted(t for t in triaged if t[0] in ran and t not in hits):
        found.append(f"triage {rule_id} {uri}: matches no result; remove the entry")
    return found


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "check":
        try:
            triage = json.loads(TRIAGE_PATH.read_text())
        except (OSError, ValueError) as exc:
            print(f"sarif-gate: unreadable {TRIAGE_PATH.name} ({exc})", file=sys.stderr)
            return 1
        found = check([Path(p) for p in argv[2:]], triage, date.today())
        for line in found:
            print(f"sarif-gate: {line}", file=sys.stderr)
        return 1 if found else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
