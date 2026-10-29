"""Security report: summary.md and report.json built from every gate's machine output.

Usage: report.py render --raw DIR --out DIR   write report.json and summary.md; exit 1 if
                                              any gate failed or never reported

With CUI_GUARD_STRICT=1 (CI's security job and the release), a SKIPPED gate also fails.

`scripts/check report` fills DIR (the raw dir) with, per gate, `<gate>.status` ("PASS|FAIL|
SKIPPED <seconds> [reason]"), junit XML for the pytest gates, `audit-<lock>-<source>.json`
from pip-audit, `sbom.sha256`, `build-a.digests`, `build-b.digests` and `tools.txt`.

The report carries only counts, rule and advisory IDs, package names, versions, digests and
tool versions. Junit text, advisory descriptions and test names are never read into it.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATES = ["lint", "lock", "test", "perf", "leak", "fuzz", "audit", "secrets", "workflows", "sbom", "build", "fips"]  # fmt: skip
PYTEST_GATES = ("test", "perf", "leak", "fuzz")
STATUSES = {"PASS", "FAIL", "SKIPPED"}
HEX64 = re.compile(r"[0-9a-f]{64}")
SAFE_NAME = re.compile(r"[A-Za-z0-9._+-]{1,200}")
# Only the reasons scripts/check writes are echoed; anything else is dropped.
KNOWN_REASONS = {"gitleaks not installed; runs in CI", "no workflows yet", "docker not available"}
AUDIT_FILES = [
    f"audit-{lock}-{src}.json" for lock in ("runtime", "dev") for src in ("pypi", "osv")
]


def _load(path: Path, name: str):
    # Load by path: the tests/ and scripts/ directories are not importable packages.
    spec = importlib.util.spec_from_file_location(name, path)
    if not (spec and spec.loader):
        raise ImportError(path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def gate_status(raw: Path, gate: str) -> dict:
    try:
        parts = (raw / f"{gate}.status").read_text().split(maxsplit=2)
    except OSError:
        return {"status": "MISSING", "seconds": None}
    status = parts[0] if parts and parts[0] in STATUSES else "FAIL"
    try:
        seconds: int | None = int(parts[1])
    except (IndexError, ValueError):
        seconds = None
    out: dict = {"status": status, "seconds": seconds}
    reason = parts[2].strip() if len(parts) > 2 else ""
    if status == "SKIPPED" and reason in KNOWN_REASONS:
        out["reason"] = reason
    return out


def junit_counts(path: Path) -> dict | None:
    """Counts only; failure text, messages and test names are never read out."""
    try:
        tree = ET.parse(path)  # noqa: S314 - our own pytest output
    except (OSError, ET.ParseError):
        return None
    counts = {"passed": 0, "failed": 0, "xfailed": 0, "skipped": 0}
    for case in tree.iter("testcase"):
        if case.find("failure") is not None or case.find("error") is not None:
            counts["failed"] += 1
        elif (skip := case.find("skipped")) is not None:
            xfail = (skip.get("type") or "") == "pytest.xfail"
            counts["xfailed" if xfail else "skipped"] += 1
        else:
            counts["passed"] += 1
    return counts


def dependency_findings(raw: Path, triaged: set[str]) -> tuple[list[dict], int, int]:
    """Findings plus counts of omitted (unsafe ID or name) findings and unusable audit files."""
    found: dict[tuple, dict] = {}
    omitted = 0
    unreadable = sum(1 for n in AUDIT_FILES if not (raw / n).is_file())
    for path in sorted(raw.glob("audit-*.json")):
        lock, _, source = path.stem.removeprefix("audit-").partition("-")
        try:
            deps = json.loads(path.read_text())["dependencies"]
            if not isinstance(deps, list):
                raise TypeError
            vulns = [(d, v) for d in deps for v in d.get("vulns", [])]
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            if path.name in AUDIT_FILES:
                unreadable += 1
            continue
        for dep, vuln in vulns:
            ids = [vuln.get("id"), *vuln.get("aliases", [])]
            name, version = str(dep.get("name")), str(dep.get("version"))
            if not all(
                isinstance(i, str) and SAFE_NAME.fullmatch(i) for i in ids
            ) or not (SAFE_NAME.fullmatch(name) and SAFE_NAME.fullmatch(version)):
                omitted += 1
                continue
            key = (lock, name, version, ids[0])
            entry = found.setdefault(
                key,
                {
                    "id": ids[0],
                    "aliases": sorted(set(ids[1:])),
                    "package": name,
                    "version": version,
                    "lock": lock,
                    "sources": [],
                    "vex": "triaged" if set(ids) & triaged else "untriaged",
                },
            )
            entry["sources"] = sorted({*entry["sources"], source})
    rows = sorted(found.values(), key=lambda e: (e["lock"], e["package"], e["id"]))
    return rows, omitted, unreadable


def known_gaps() -> list[str]:
    mod = _load(ROOT / "tests" / "redteam" / "transforms.py", "cui_redteam_transforms")
    return sorted(f"{t}/{k}" for (t, k), v in mod.EXPECTED.items() if v == "KNOWN_GAP")


def read_digests(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return out
    for line in lines:
        digest, _, name = line.partition("  ")
        if HEX64.fullmatch(digest) and SAFE_NAME.fullmatch(name):
            out[name] = digest
    return out


def git(*args: str) -> str | None:
    try:
        done = subprocess.run(  # noqa: S603 - fixed git argv
            ["git", "-C", str(ROOT), *args],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return done.stdout.strip()


def tool_versions(raw: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        lines = (raw / "tools.txt").read_text().splitlines()
    except OSError:
        return out
    for line in lines:
        name, _, version = line.partition(" ")
        if SAFE_NAME.fullmatch(name) and SAFE_NAME.fullmatch(version):
            out[name] = version
    return out


def strict_mode() -> bool:
    return os.environ.get("CUI_GUARD_STRICT") == "1"


def build_report(raw: Path) -> dict:
    errors: list[str] = []
    strict = strict_mode()

    def section(name: str, fn, default):
        try:
            return fn()
        except Exception:  # noqa: BLE001 - recorded by name only, never by message
            errors.append(f"{name}: failed to build")
            return default

    def triaged_ids() -> set[str]:
        vex = _load(ROOT / "scripts" / "security" / "vex.py", "cui_vex")
        return set(vex.ignored_ids(vex._load()))

    gates = {g: gate_status(raw, g) for g in GATES}
    tests = {g: junit_counts(raw / f"{g}.xml") for g in PYTEST_GATES}
    for g, counts in tests.items():
        if gates[g]["status"] != "PASS":
            continue
        if counts is None:
            gates[g].update(status="FAIL", note="junit missing or unreadable")
        elif counts["failed"]:
            gates[g].update(status="FAIL", note="junit reports failures")
    findings, omitted, unreadable = section(
        "dependency findings",
        lambda: dependency_findings(raw, section("vex", triaged_ids, set())),
        ([], 0, 0),
    )
    audit_ran = gates["audit"]["status"] != "SKIPPED"
    if omitted:
        errors.append(f"{omitted} findings omitted (unsafe ID or name)")
    if unreadable and audit_ran:
        errors.append(f"{unreadable} audit results missing or unreadable")
    sbom = ""
    try:
        sbom = (raw / "sbom.sha256").read_text().strip()
    except OSError:
        pass
    sbom_ok = bool(HEX64.fullmatch(sbom))
    if gates["sbom"]["status"] != "SKIPPED" and not sbom_ok:
        errors.append("SBOM digest missing")
    a, b = read_digests(raw / "build-a.digests"), read_digests(raw / "build-b.digests")
    reproducible = bool(a) and a == b
    if gates["build"]["status"] != "SKIPPED" and not reproducible:
        errors.append("build digests missing or not reproducible")
    commit = git("rev-parse", "HEAD")
    gaps = section("known gaps", known_gaps, [])
    skipped = [g for g, v in gates.items() if v["status"] == "SKIPPED"]
    passing = ("PASS",) if strict else ("PASS", "SKIPPED")
    ok = not errors and all(v["status"] in passing for v in gates.values())
    return {
        "ok": ok,
        "strict": strict,
        "errors": errors,
        "skipped_gates": skipped,
        "commit": commit or "unknown",
        "dirty": bool(git("status", "--porcelain")),
        "date": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": tool_versions(raw),
        "gates": gates,
        "tests": {g: c for g, c in tests.items() if c is not None},
        "dependency_findings": findings,
        "omitted_findings": omitted,
        "unreadable_audit_results": unreadable,
        "known_gaps": gaps,
        "sbom_sha256": sbom if sbom_ok else None,
        "build_digests": {"a": a, "b": b, "reproducible": reproducible},
    }


def render_summary(r: dict) -> str:
    lines = [
        "# cui-guard security report",
        "",
        f"Overall: {'PASS' if r['ok'] else 'FAIL'}"
        + (
            f" ({len(r['skipped_gates'])} skipped: {', '.join(r['skipped_gates'])})"
            if r["skipped_gates"]
            else ""
        ),
        "Mode: strict (a skipped gate fails)"
        if r["strict"]
        else "Mode: local (skipped gates pass)",
        f"Commit: {r['commit']}{' (dirty tree)' if r['dirty'] else ''}",
        f"Date: {r['date']}",
        "Tools: " + (", ".join(f"{k} {v}" for k, v in r["tools"].items()) or "none"),
        "",
        "## Gates",
        "",
        "| Gate | Status | Seconds | Note |",
        "| --- | --- | --- | --- |",
    ]
    for name, g in r["gates"].items():
        sec = "" if g["seconds"] is None else g["seconds"]
        lines.append(
            f"| {name} | {g['status']} | {sec} | {g.get('reason') or g.get('note', '')} |"
        )
    lines += [
        "",
        "## Test counts",
        "",
        "| Gate | Passed | Failed | Xfailed | Skipped |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name, c in r["tests"].items():
        lines.append(
            f"| {name} | {c['passed']} | {c['failed']} | {c['xfailed']} | {c['skipped']} |"
        )
    if r["errors"]:
        lines += ["", "## Report errors", ""] + [f"- {e}" for e in r["errors"]]
    lines += ["", "## Dependency findings", ""]
    if r["dependency_findings"]:
        lines += [
            "| ID | Package | Version | Lock | VEX |",
            "| --- | --- | --- | --- | --- |",
        ]
        for f in r["dependency_findings"]:
            lines.append(
                f"| {f['id']} | {f['package']} | {f['version']} | {f['lock']} | {f['vex']} |"
            )
    else:
        lines.append("None.")
    lines += [
        "",
        f"## Known red-team gaps ({len(r['known_gaps'])})",
        "",
        ", ".join(r["known_gaps"]) or "None.",
        "",
        "## SBOM",
        "",
        f"SHA-256: {r['sbom_sha256'] or 'unavailable'}",
        "",
        "## Reproducible build",
        "",
        f"Two builds identical: {'yes' if r['build_digests']['reproducible'] else 'no'}",
        "",
    ]
    for name, digest in r["build_digests"]["a"].items():
        lines.append(f"- {name}: {digest}")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    rd = sub.add_parser("render")
    rd.add_argument("--raw", required=True, type=Path)
    rd.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    report = build_report(args.raw)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (args.out / "summary.md").write_text(render_summary(report))
    passing = ("PASS",) if report["strict"] else ("PASS", "SKIPPED")
    bad = [g for g, s in report["gates"].items() if s["status"] not in passing]
    for g in bad:
        print(f"gate {g}: {report['gates'][g]['status']}", file=sys.stderr)
    for e in report["errors"]:
        print(f"report error: {e}", file=sys.stderr)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
