from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Load by path: the name "redteam" is a test package, not importable as a library.
_spec = importlib.util.spec_from_file_location(
    "cui_redteam_transforms", ROOT / "tests" / "redteam" / "transforms.py"
)
assert _spec and _spec.loader
_transforms = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_transforms)


def read(rel: str) -> str:
    return (ROOT / rel).read_text()


def test_security_md_sections():
    text = read("SECURITY.md")
    headings = {
        m.group(1).strip().lower()
        for m in re.finditer(r"^#+\s+(.+)$", text, re.MULTILINE)
    }
    for needed in (
        "reporting",
        "supported versions",
        "response targets",
        "disclosure",
        "scope",
        "safe harbor",
    ):
        assert needed in headings, needed
    assert "Report a vulnerability" in text
    assert "private vulnerability reporting" in text and "fill in before publishing" not in text
    assert "`cui-guard doctor` reports `end-of-life`" in text and "end of life" in text
    assert "planned, not yet shipped" not in text and "TODO" not in text


def test_fips_doc_framing():
    text = read("docs/FIPS.md")
    assert "it uses the platform's FIPS provider, and it refuses to start unless that provider reports itself active" in text
    assert "validated module" not in text
    assert "cite the platform vendor's CMVP certificate" in text
    assert "Tested on **Red Hat UBI 9** only" in text and "expected to work but are untested" in text
    assert "FIPS compliant" not in text
    for check in (
        "`os`",
        "`openssl-fips-provider`",
        "`hashlib-openssl`",
        "`kernel-fips`",
    ):
        assert check in text, check


def test_no_compliance_claims():
    banned = re.compile(
        r"\b(FedRAMP|CMMC|ATO)\b[^.\n]*\b(compliant|certified|authorized|approved)\b"
        r"|\bSLSA (Build )?(Level|L)\s*[34]\b|\bcompliant\b",
        re.IGNORECASE,
    )
    scanned = [
        ROOT / "SECURITY.md",
        *(ROOT / "docs").glob("*.md"),
        *(ROOT / "docs" / "compliance").glob("*.md"),
        ROOT / "docs" / "FIPS.md",
        ROOT / "README.md",
    ]
    for p in scanned:
        assert not banned.search(p.read_text()), p


def test_threat_model_names_existing_tests():
    text = read("docs/THREAT-MODEL.md")
    paths = set(re.findall(r"\btests/[\w./-]+", text))
    assert paths
    for rel in paths:
        assert (ROOT / rel.rstrip(".")).exists(), rel
    for t in range(1, 8):
        assert re.search(rf"^#+\s+T{t}\b", text, re.MULTILINE), f"T{t}"


def test_assurance_lists_every_known_gap():
    text = read("docs/SECURITY-ASSURANCE.md")
    gaps = {t for (t, _kind), v in _transforms.EXPECTED.items() if v == "KNOWN_GAP"}
    assert gaps
    for transform in gaps:
        assert f"`{transform}`" in text, transform
    assert "SLSA Build Level 2 as GitHub implements it; no claim beyond that" in text
    assert "OSTIF" in text and "Best Practices" in text


def test_maintainer_checklist_items():
    text = read("docs/MAINTAINER-SECURITY.md")
    assert (
        "- [ ] Enable Dependabot security updates (exempt from the 7-day cooldown)"
        in text
    )
    assert len(re.findall(r"^- \[ \] ", text, re.MULTILINE)) >= 8
