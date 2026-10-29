"""Triage records for the gating scanners: a CycloneDX VEX file whose dismissals expire.

Usage: vex.py ids                    print the triaged IDs
       vex.py check [AUDIT_JSON...]  exit 1 on any problem. Each AUDIT_JSON is an unfiltered
                                     `pip-audit -f json` result: findings not triaged in the VEX
                                     fail, and VEX entries matching no finding are flagged
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
        if not entry.get("id"):
            out.append(f"{vid}: missing field id")
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
        if recorded is not None and recorded > today:
            out.append(f"{vid}: recorded date is in the future")
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


def audit_findings(report: dict) -> list[set[str]]:
    """One set per finding: its ID plus aliases (pip-audit ignores by either).

    Raises ValueError for anything that is not a complete pip-audit report: no
    `dependencies` list, or a dependency pip-audit skipped (the --strict guarantee).
    """
    deps = report.get("dependencies") if isinstance(report, dict) else None
    if not isinstance(deps, list):
        raise TypeError("no dependencies list")
    for dep in deps:
        if dep.get("skip_reason"):
            raise ValueError(
                f"dependency {dep.get('name')} was not audited: {dep['skip_reason']}"
            )
    return [
        {v["id"], *v.get("aliases", [])} for dep in deps for v in dep.get("vulns", [])
    ]


def _load() -> dict:
    return json.loads(VEX_PATH.read_text())


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "ids":
        print("\n".join(ignored_ids(_load())))
        return 0
    if len(argv) >= 2 and argv[1] == "check":
        vex = _load()
        triaged = set(ignored_ids(vex))
        audited: set[str] | None = None
        found: list[str] = []
        if len(argv) > 2:
            audited = set()
            for path in argv[2:]:
                try:
                    report = json.loads(Path(path).read_text())
                    findings = audit_findings(report)
                except (
                    OSError,
                    ValueError,
                    KeyError,
                    TypeError,
                    AttributeError,
                ) as exc:
                    found.append(
                        f"{path}: unusable pip-audit result, audit incomplete ({exc})"
                    )
                    continue
                for ids in findings:
                    audited |= ids
                    if not ids & triaged:
                        found.append(
                            f"untriaged vulnerability {sorted(ids)} reported in {Path(path).name}"
                        )
        found += problems(vex, date.today(), audited)
        for line in found:
            print(f"vex: {line}", file=sys.stderr)
        return 1 if found else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
