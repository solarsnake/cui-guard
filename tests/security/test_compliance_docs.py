from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPLIANCE = ROOT / "docs" / "compliance"
DISCLAIMER = "It does not certify, assess or authorize anything."
ROOT_FILE_RE = re.compile(r"^[\w.-]+\.(?:lock|md|py|toml|txt|yml|yaml|json)$")
PATH_RE = re.compile(
    r"^(?:(?:src|tests|scripts|\.github|docs|security|requirements)/[\w./-]+)$"
)


def docs() -> list[Path]:
    found = sorted(COMPLIANCE.glob("*.md"))
    assert {p.name for p in found} >= {
        "README.md",
        "SSDF.md",
        "800-171.md",
        "800-53.md",
    }
    return found


def first_cells(name: str, column: int = 0) -> list[str]:
    cells = []
    for line in (COMPLIANCE / name).read_text().splitlines():
        if line.startswith("|"):
            parts = [c.strip() for c in line.strip().strip("|").split("|")]
            cells.append(parts[column].strip("`"))
    return cells


def test_every_doc_has_the_disclaimer():
    for p in docs():
        assert DISCLAIMER in p.read_text(), p.name


def test_ssdf_lists_all_19_practices():
    want = {f"PO.{i}" for i in range(1, 6)} | {f"PS.{i}" for i in range(1, 4)}
    want |= {"PW.1", "PW.2"} | {f"PW.{i}" for i in range(4, 10)}
    want |= {f"RV.{i}" for i in range(1, 4)}
    assert len(want) == 19
    got = [c for c in first_cells("SSDF.md") if re.fullmatch(r"[A-Z]{2}\.\d", c)]
    assert set(got) == want
    assert len(got) == 19  # no duplicates
    text = (COMPLIANCE / "SSDF.md").read_text()
    assert "Practice | Title | Project evidence | Responsibility" in text
    for line in text.splitlines():
        if re.match(r"\| `?[A-Z]{2}\.\d`? ", line):
            assert line.strip().strip("|").split("|")[-1].strip() in {
                "project",
                "maintainer",
                "producer",
            }, line


def test_800_171_rows():
    text = (COMPLIANCE / "800-171.md").read_text()
    header = (
        "Rev 2 | Rev 3 | Title | What cui-guard contributes | Configuration"
        " | Customer responsibility | Suggested SSP statement"
    )
    assert header in text
    rev2 = set(first_cells("800-171.md", 0))
    rev3 = set(first_cells("800-171.md", 1))
    assert {
        "3.1.3",
        "3.3.1",
        "3.3.2",
        "3.3.8",
        "3.13.1",
        "3.13.8",
        "3.13.11",
        "3.14.1",
    } <= rev2
    assert {"03.17.01", "03.17.02", "03.17.03"} <= rev3


def test_800_53_rows():
    want = {
        "AC-4", "AU-2", "AU-3", "AU-9", "SC-7", "SC-8", "SC-13",
        "SI-2", "SA-11", "SA-15", "SR-3", "SR-4", "SR-11", "CM-8",
    }  # fmt: skip
    got = [c for c in first_cells("800-53.md") if re.fullmatch(r"[A-Z]{2}-\d+", c)]
    assert set(got) == want and len(got) == len(want)
    assert (
        "Control | Title | What cui-guard contributes | Evidence"
        in (COMPLIANCE / "800-53.md").read_text()
    )


def test_every_cited_path_exists():
    cited = 0
    for p in docs():
        for token in re.findall(r"`([^`\n]+)`", p.read_text()):
            if PATH_RE.match(token) or ROOT_FILE_RE.match(token):
                cited += 1
                assert (ROOT / token).exists(), f"{p.name}: {token}"
    assert cited > 40


def test_status_notes_are_dated():
    for p in docs():
        for line in p.read_text().splitlines():
            if re.search(r"CMMC|class deviation", line, re.IGNORECASE):
                assert "as of 20" in line.lower(), f"{p.name}: {line[:80]}"
