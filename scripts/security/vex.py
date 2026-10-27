"""Triage records for the gating scanners: a CycloneDX VEX file whose dismissals expire.

Usage: vex.py ids                      print the IDs to pass to pip-audit --ignore-vuln
       vex.py check [AUDITED_IDS...]   exit 1 on any problem; AUDITED_IDS (optional) are
                                       the IDs the audit reported, so stale entries show up
"""

from __future__ import annotations

import json
import sys
from datetime import date, timedelta
from pathlib import Path

VEX_PATH = Path(__file__).resolve().parents[2] / "security" / "vex.cdx.json"
STATES = {"not_affected", "false_positive", "resolved"}
MAX_DAYS = 90
REVIEW_BY = "cui-guard:review-by"
RECORDED = "cui-guard:recorded"


def ignored_ids(vex: dict) -> list[str]:
    return [v["id"] for v in vex.get("vulnerabilities", []) if v.get("id")]


def _prop(entry: dict, name: str) -> str | None:
    for p in entry.get("properties", []):
        if p.get("name") == name:
            return p.get("value")
    return None


def _date(text: str | None) -> date | None:
    try:
        return date.fromisoformat(text) if text else None
    except ValueError:
        return None


def problems(vex: dict, today: date, audited_ids: set[str] | None) -> list[str]:
    out: list[str] = []
    for entry in vex.get("vulnerabilities", []):
        vid = entry.get("id") or "<no id>"
        analysis = entry.get("analysis") or {}
        if analysis.get("state") not in STATES:
            out.append(f"{vid}: analysis.state must be one of {sorted(STATES)}")
        for field in ("justification", "detail"):
            if not analysis.get(field):
                out.append(f"{vid}: missing analysis.{field}")
        review_by = _date(_prop(entry, REVIEW_BY))
        recorded = _date(_prop(entry, RECORDED))
        if review_by is None:
            out.append(f"{vid}: missing or invalid {REVIEW_BY}")
        if recorded is None:
            out.append(f"{vid}: missing or invalid {RECORDED}")
        if review_by is not None and review_by < today:
            out.append(f"{vid}: review-by {review_by} expired (today is {today})")
        if (
            review_by is not None
            and recorded is not None
            and review_by > recorded + timedelta(days=MAX_DAYS)
        ):
            out.append(
                f"{vid}: review-by {review_by} is more than {MAX_DAYS} days after recorded {recorded}"
            )
        if audited_ids is not None and vid not in audited_ids:
            out.append(f"{vid}: matches no finding in the audit; remove the entry")
    return out


def _load() -> dict:
    return json.loads(VEX_PATH.read_text())


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "ids":
        print("\n".join(ignored_ids(_load())))
        return 0
    if len(argv) >= 2 and argv[1] == "check":
        audited = set(argv[2:]) if len(argv) > 2 else None
        found = problems(_load(), date.today(), audited)
        for line in found:
            print(f"vex: {line}", file=sys.stderr)
        return 1 if found else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
