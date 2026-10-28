"""CycloneDX SBOM of the runtime dependency set, checked against CISA's minimum elements.

Usage: sbom.py build --out PATH   build the SBOM from requirements/runtime.lock.txt
       sbom.py check PATH         exit 1, listing every missing minimum element

The SBOM covers the hash-pinned runtime lock plus a root component for cui-guard itself.
`SOURCE_DATE_EPOCH`, when set, fixes the timestamp so rebuilds are byte-identical.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "requirements" / "runtime.lock.txt"
PYPROJECT = ROOT / "pyproject.toml"
PROJECT = "cui-guard"
SUPPLIER = "cui-guard contributors"
# cyclonedx-py reads no package metadata from a lock file, so components get the index
# they are installed from as supplier.
INDEX_SUPPLIER = {
    "name": "Python Package Index (pypi.org)",
    "url": ["https://pypi.org/"],
}


def parse_lock(text: str) -> dict[str, dict]:
    """name -> {version, hashes, via}. `via` holds the names that require the package."""
    pkgs: dict[str, dict] = {}
    for block in re.finditer(
        r"^([A-Za-z0-9_.-]+)==(\S+)[^\n]*\n((?:[ \t]+[^\n]*\n?)*)", text, re.MULTILINE
    ):
        name, version, body = block.groups()
        via: list[str] = []
        in_via = False
        for line in body.splitlines():
            s = line.strip()
            if s.startswith("# via"):
                in_via = True
                s = s[len("# via") :].strip()
            elif in_via and s.startswith("#"):
                s = s.lstrip("#").strip()
            else:
                in_via = False
                continue
            if s:
                via.append(s)
        pkgs[name.lower()] = {
            "name": name,
            "version": version,
            "hashes": sorted(set(re.findall(r"--hash=sha256:([0-9a-f]{64})", body))),
            "via": via,
        }
    return pkgs


def cyclonedx_cmd() -> list[str]:
    local = Path(sys.executable).parent / "cyclonedx-py"
    if local.exists():
        return [str(local)]
    found = shutil.which("cyclonedx-py")
    if found:
        return [found]
    return [
        "uv",
        "tool",
        "run",
        "--python",
        "3.12",
        "--from",
        "cyclonedx-bom",
        "cyclonedx-py",
    ]


def timestamp() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    when = datetime.fromtimestamp(int(epoch), UTC) if epoch else datetime.now(UTC)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def build(out: Path) -> None:
    pkgs = parse_lock(LOCK.read_text())
    proc = subprocess.run(  # noqa: S603
        [
            *cyclonedx_cmd(),
            "requirements",
            str(LOCK),
            "--sv",
            "1.6",
            "--of",
            "JSON",
            "--output-reproducible",
        ],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONWARNINGS": "ignore"},
    )
    if proc.returncode != 0:
        sys.exit(f"cyclonedx-py failed:\n{proc.stderr}")
    bom = json.loads(proc.stdout)

    project = tomllib.loads(PYPROJECT.read_text())["project"]
    root_ref = f"pkg:pypi/{PROJECT}@{project['version']}"
    root = {
        "type": "application",
        "bom-ref": root_ref,
        "name": PROJECT,
        "version": project["version"],
        "purl": root_ref,
        "supplier": {"name": SUPPLIER},
        "licenses": [{"license": {"id": project["license"]}}],
    }

    components = []
    for comp in bom["components"]:
        pkg = pkgs[comp["name"].lower()]
        components.append(
            {
                "type": "library",
                "bom-ref": comp["purl"],
                "name": comp["name"],
                "version": comp["version"],
                "purl": comp["purl"],
                "supplier": INDEX_SUPPLIER,
                "hashes": [{"alg": "SHA-256", "content": h} for h in pkg["hashes"]],
            }
        )
    components.sort(key=lambda c: c["name"])
    refs = {c["name"].lower(): c["bom-ref"] for c in components}

    depends: dict[str, set[str]] = {
        root_ref: set(),
        **{c["bom-ref"]: set() for c in components},
    }
    for key, pkg in pkgs.items():
        for parent in pkg["via"]:
            owner = root_ref if parent == PROJECT else refs.get(parent.lower())
            if owner:
                depends[owner].add(refs[key])
    dependencies = [
        {"ref": r, "dependsOn": sorted(d)} for r, d in sorted(depends.items())
    ]

    bom["metadata"] = {
        "timestamp": timestamp(),
        "tools": bom["metadata"]["tools"],
        "component": root,
    }
    bom["components"] = components
    bom["dependencies"] = dependencies
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n")


def problems(bom: dict) -> list[str]:
    found: list[str] = []
    meta = bom.get("metadata", {})
    if not meta.get("timestamp"):
        found.append("metadata: missing timestamp")
    if not meta.get("tools"):
        found.append("metadata: missing tool metadata")
    root = meta.get("component")
    if not root:
        found.append("metadata: missing root component")
        root = {}
    components = bom.get("components", [])
    for comp in [root, *components] if root else components:
        label = comp.get("name", "?")
        if not (comp.get("supplier") or comp.get("author")):
            found.append(f"{label}: missing supplier/author")
        for field in ("name", "version", "purl"):
            if not comp.get(field):
                found.append(f"{label}: missing {field}")
    for comp in components:
        if not any(
            h.get("alg") == "SHA-256" and h.get("content")
            for h in comp.get("hashes", [])
        ):
            found.append(f"{comp.get('name', '?')}: missing SHA-256 hash")
    deps = {d.get("ref") for d in bom.get("dependencies", [])}
    if not deps:
        found.append("missing dependencies graph")
    else:
        for comp in [root, *components] if root else components:
            if comp.get("bom-ref") not in deps:
                found.append(
                    f"{comp.get('name', '?')}: not covered by the dependencies graph"
                )
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--out", required=True, type=Path)
    c = sub.add_parser("check")
    c.add_argument("path", type=Path)
    args = ap.parse_args()
    if args.cmd == "build":
        build(args.out)
        return 0
    try:
        bom = json.loads(args.path.read_text())
    except (OSError, ValueError) as exc:
        print(f"unreadable SBOM {args.path}: {exc}", file=sys.stderr)
        return 1
    found = problems(bom)
    for line in found:
        print(line, file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
