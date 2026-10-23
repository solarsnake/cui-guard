from pathlib import Path

import pytest

from cui_guard.detect.rules import load_builtin_rules, scan_rules
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


@pytest.mark.parametrize("text", ["C\u200bUI//SP-CTI", "ＳＥＣＲＥＴ//ＮＯＦＯＲＮ"])
def test_zero_width_and_fullwidth_markings_detected(text):
    assert classes(text) & MARKING


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
