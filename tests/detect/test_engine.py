import importlib.util
import itertools

from cui_guard.detect import engine
from cui_guard.detect.engine import Detector
from cui_guard.detect.identifiers import IdentifierConfig
from cui_guard.detect.ner import load_presidio
from cui_guard.detect.rules import load_builtin_rules
from cui_guard.model import DetClass, Hit


def make(ner=None):
    return Detector(load_builtin_rules(), IdentifierConfig(), ner)


def test_union_of_sources():
    key = "sk-" + "ant-" + "A" * 24
    text = f"CUI//SP-CTI\nconnect to jira.ops.example.mil with {key}"
    classes = {h.cls for h in make().scan(text)}
    assert DetClass.CUI_MARKING in classes
    assert DetClass.IDENTIFIER in classes
    assert DetClass.SECRET in classes


def test_overlap_resolution():
    text = "https://user:pw123@db.example.mil"
    hits = [h for h in make().scan(text) if h.kind is not None]
    assert {h.value for h in hits} >= {"pw123", "db.example.mil"}
    spans = sorted((h.start, h.end) for h in hits)
    assert all(a[1] <= b[0] for a, b in itertools.pairwise(spans))


def test_overlap_longest_wins_secret_ties():
    class Fake:
        def analyze(self, text):
            return [Hit("ner.person", DetClass.IDENTIFIER, 0, 5, text[:5], "person")]

    hits = make(Fake())._scan_uncached("alice")
    assert [(h.rule_id, h.end) for h in hits] == [("ner.person", 5)]
    a = Hit("a", DetClass.IDENTIFIER, 0, 5, "x" * 5, "host")
    b = Hit("b", DetClass.SECRET, 0, 5, "x" * 5, "secret")
    c = Hit("c", DetClass.IDENTIFIER, 0, 3, "xxx", "term")
    assert engine._resolve_overlaps([a, b, c]) == [b]


def test_marking_hits_not_dropped_by_overlap():
    m = Hit("m", DetClass.CUI_MARKING, 0, 10, "x" * 10)
    s = Hit("s", DetClass.SECRET, 2, 4, "xx", "secret")
    assert engine._resolve_overlaps([m, s]) == [m, s]


def test_duplicate_hits_deduped():
    a = Hit("z.rule", DetClass.CUI_MARKING, 0, 5, "x" * 5)
    b = Hit("a.rule", DetClass.CUI_MARKING, 0, 5, "x" * 5, verified=False)
    c = Hit("b.rule", DetClass.CUI_MARKING, 0, 5, "x" * 5)
    assert engine._dedupe([a, b, c]) == [c]
    assert engine._dedupe([a, b]) == [a]


def test_cache_hit(monkeypatch):
    calls = []
    real = engine.scan_rules

    def counting(text, rules):
        calls.append(1)
        return real(text, rules)

    monkeypatch.setattr(engine, "scan_rules", counting)
    d = make()
    first = d.scan("hello db.example.mil")
    first.append("junk")
    second = d.scan("hello db.example.mil")
    assert len(calls) == 1
    assert "junk" not in second
    assert d.scan("hello db.example.mil") is not second


def test_ner_hits_included():
    class Fake:
        def analyze(self, text):
            return [Hit("ner.person", DetClass.IDENTIFIER, 6, 11, "Alice", "person")]

    hits = make(Fake()).scan("hello Alice")
    assert any(h.kind == "person" and h.value == "Alice" for h in hits)


def test_ner_absent_is_none(monkeypatch):
    monkeypatch.setattr(importlib.util, "find_spec", lambda name, *a, **k: None)
    assert load_presidio() is None
