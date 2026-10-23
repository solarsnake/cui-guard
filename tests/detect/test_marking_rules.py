from pathlib import Path

import pytest

from cui_guard.detect.rules import load_builtin_rules, rules_from_patterns, scan_rules
from cui_guard.model import DetClass

CORPUS = Path(__file__).parent.parent / "corpus" / "positive"
CLASSIFIED_FILES = sorted((CORPUS / "classified").glob("*.txt"))
CUI_FILES = sorted((CORPUS / "cui").glob("*.txt"))
RULES = load_builtin_rules()
MARKING = {DetClass.CLASSIFIED_MARKING, DetClass.CUI_MARKING}


def classes(text: str) -> set[DetClass]:
    return {h.cls for h in scan_rules(text, RULES)}


def test_corpus_present():
    assert CLASSIFIED_FILES and CUI_FILES


@pytest.mark.parametrize("path", CLASSIFIED_FILES, ids=lambda p: p.name)
def test_classified_corpus(path):
    assert DetClass.CLASSIFIED_MARKING in classes(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", CUI_FILES, ids=lambda p: p.name)
def test_cui_corpus(path):
    assert DetClass.CUI_MARKING in classes(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "text",
    [
        "SECRET//NOFORN",
        "TOP SECRET//SI//TK//NOFORN",
        "(S//NF) The",
        "Classified By: J. Doe",
        "Declassify On: 20501231",
    ],
)
def test_classified_banners(text):
    assert DetClass.CLASSIFIED_MARKING in classes(text)


@pytest.mark.parametrize(
    "text",
    [
        "CUI",
        "CUI//SP-CTI",
        "CUI//SP-EXPT//NOFORN",
        "(CUI) text",
        "Controlled by: Dept of X",
        "CUI Category: ISVI",
        "FOR OFFICIAL USE ONLY",
        "FOUO",
        "Distribution Statement D",
        (
            "WARNING - This document contains technical data whose export is "
            "restricted by the Arms Export Control Act (Title 22, U.S.C., Sec 2751 et seq.)"
        ),
    ],
)
def test_cui_banners(text):
    assert DetClass.CUI_MARKING in classes(text)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("C\u200bUI//SP-CTI", DetClass.CUI_MARKING),
        (
            "\uff33\uff25\uff23\uff32\uff25\uff34//\uff2e\uff2f\uff26\uff2f\uff32\uff2e",
            DetClass.CLASSIFIED_MARKING,
        ),
    ],
)
def test_zero_width_and_fullwidth_markings_detected(text, expected):
    assert expected in classes(text)


def test_zero_width_hit_maps_to_original_offsets():
    text = "x\nC\u200bUI//SP-CTI\ny"
    hits = [h for h in scan_rules(text, RULES) if h.cls is DetClass.CUI_MARKING]
    assert hits
    assert all(text[h.start : h.end] == h.value for h in hits)
    assert any(h.value == "C\u200bUI//SP-CTI" for h in hits)


@pytest.mark.parametrize(
    "text",
    [
        "the secret to good soup",
        "a cuisine review",
        "this is a note (s) plural marker in a sentence",
        "(s) plural marker in a sentence",
        "See section (c) below",
    ],
)
def test_no_false_positive_on_prose(text):
    assert not classes(text) & MARKING


def test_unverified_rules_flagged():
    unverified = [r for r in RULES if r.source == "model-knowledge"]
    assert unverified
    assert all(r.verified is False for r in unverified)


@pytest.mark.parametrize(
    "text",
    [
        "(C) 2024 Example Corp",
        "(c) 2024 Example Corp",
        "(C) Copyright 2023 Foo",
        "(C)2024 Foo",
        "(C) © Foo",
    ],
)
def test_copyright_lines_not_classified(text):
    assert DetClass.CLASSIFIED_MARKING not in classes(text)


@pytest.mark.parametrize(
    "text", ["(C) The following paragraph", "(TS//SI) text", "(S//NF) text"]
)
def test_portion_marks_still_hit(text):
    assert DetClass.CLASSIFIED_MARKING in classes(text)


@pytest.mark.parametrize(
    "text", ["This value is derived from the input", "classified by size"]
)
def test_handling_words_in_prose_not_classified(text):
    assert DetClass.CLASSIFIED_MARKING not in classes(text)


@pytest.mark.parametrize(
    "text",
    ["derived from: SCG 2023", "Classified By: J. Doe", "declassify on: 20501231"],
)
def test_authority_block_case_insensitive(text):
    assert DetClass.CLASSIFIED_MARKING in classes(text)


@pytest.mark.parametrize(
    "text", ["foo\rSECRET//NOFORN", "foo\u2028SECRET//NOFORN", "a\nSECRET"]
)
def test_line_separators_anchor_banners(text):
    assert DetClass.CLASSIFIED_MARKING in classes(text)


@pytest.mark.parametrize("text", ["\u0106UI//SP-CTI", "C\u0301UI//SP-CTI"])
def test_combining_marks_stripped(text):
    assert DetClass.CUI_MARKING in classes(text)


@pytest.mark.parametrize("text", ["see https://SAP.com/x", "http://SI.example"])
def test_urls_not_control_markings(text):
    assert DetClass.CLASSIFIED_MARKING not in classes(text)


def test_control_markings_still_hit():
    assert DetClass.CLASSIFIED_MARKING in classes("SECRET//SI//NOFORN")
    assert DetClass.CLASSIFIED_MARKING in classes("x //SI/TK//NOFORN")


def test_rules_from_patterns_valid():
    (r,) = rules_from_patterns(
        [{"id": "org-1", "class": "identifier", "regex": r"ACME-\d+", "kind": "PROJ"}],
        "org.toml",
    )
    assert (r.id, r.cls, r.kind, r.verified, r.source) == (
        "org-1",
        DetClass.IDENTIFIER,
        "PROJ",
        True,
        "org.toml",
    )
    assert [h.value for h in scan_rules("see ACME-42", [r])] == ["ACME-42"]


@pytest.mark.parametrize(
    ("entry", "needle"),
    [
        ({"id": "a", "class": "identifier", "regex": "("}, "patterns[1]"),
        ({"id": "a", "class": "nope", "regex": "x"}, "unknown class"),
        ({"id": "a", "class": "identifier"}, "'regex'"),
        ({"class": "identifier", "regex": "x"}, "'id'"),
    ],
)
def test_rules_from_patterns_errors(entry, needle):
    good = {"id": "g", "class": "identifier", "regex": "x"}
    with pytest.raises(ValueError, match=r"patterns\[1\]") as ei:
        rules_from_patterns([good, entry], "org.toml")
    assert needle in str(ei.value) or needle == "patterns[1]"
