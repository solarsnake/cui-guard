import importlib.util
import itertools
import sys
import threading
import types

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
    assert engine._resolve_overlaps([a, b, c], "x" * 5) == [b]


def test_marking_hits_not_dropped_by_overlap():
    m = Hit("m", DetClass.CUI_MARKING, 0, 10, "x" * 10)
    s = Hit("s", DetClass.SECRET, 2, 4, "xx", "secret")
    assert engine._resolve_overlaps([m, s], "x" * 10) == [m, s]


def test_duplicate_hits_deduped():
    a = Hit("z.rule", DetClass.CUI_MARKING, 0, 5, "x" * 5)
    b = Hit("a.rule", DetClass.CUI_MARKING, 0, 5, "x" * 5, verified=False)
    c = Hit("b.rule", DetClass.CUI_MARKING, 0, 5, "x" * 5)
    assert engine._dedupe([a, b, c]) == [c]
    assert engine._dedupe([a, b]) == [a]


def test_cache_hit(monkeypatch):
    calls = {"rules": 0, "ident": 0, "heur": 0}

    def wrap(name, key):
        real = getattr(engine, name)

        def counting(*a, **k):
            calls[key] += 1
            return real(*a, **k)

        monkeypatch.setattr(engine, name, counting)

    wrap("scan_rules", "rules")
    wrap("identifier_hits", "ident")
    wrap("controlled_content_hits", "heur")
    d = make()
    first = d.scan("hello db.example.mil")
    first.append("junk")
    second = d.scan("hello db.example.mil")
    assert calls == {"rules": 1, "ident": 1, "heur": 1}
    assert "junk" not in second
    assert d.scan("hello db.example.mil") is not second


def test_cache_thread_safe():
    d = make()
    texts = [f"host{i}.example.mil and 10.0.0.{i}" for i in range(4)]
    expected = {t: make().scan(t) for t in texts}
    errors = []

    def work():
        try:
            for n in range(200):
                t = texts[n % 4]
                assert d.scan(t) == expected[t]
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


def test_ner_partial_overlap_merges_into_host():
    text = "0123456789 db.example.mil"
    ner = Hit("ner.person", DetClass.IDENTIFIER, 0, 12, text[0:12], "person")
    host = Hit("id.host", DetClass.IDENTIFIER, 11, 25, text[11:25], "host")
    out = engine._resolve_overlaps([ner, host], text)
    assert len(out) == 1
    assert (out[0].start, out[0].end, out[0].kind) == (0, 25, "host")
    assert out[0].value == text[0:25]


def test_secret_partial_overlap_merges_as_secret():
    text = "abcdefghij klmnopqrst"
    sec = Hit("secret.x", DetClass.SECRET, 0, 8, text[0:8], "secret")
    host = Hit("id.host", DetClass.IDENTIFIER, 5, 15, text[5:15], "host")
    out = engine._resolve_overlaps([host, sec], text)
    assert len(out) == 1
    assert (out[0].start, out[0].end, out[0].kind) == (0, 15, "secret")
    assert out[0].cls is DetClass.SECRET


def test_contained_hit_absorbed_priority_decides_kind():
    text = "x" * 20
    ner = Hit("ner.person", DetClass.IDENTIFIER, 0, 20, text, "person")
    host = Hit("id.host", DetClass.IDENTIFIER, 5, 10, text[5:10], "host")
    out = engine._resolve_overlaps([ner, host], text)
    assert [(h.start, h.end, h.kind) for h in out] == [(0, 20, "host")]


def test_ner_hits_included():
    class Fake:
        def analyze(self, text):
            return [Hit("ner.person", DetClass.IDENTIFIER, 6, 11, "Alice", "person")]

    hits = make(Fake()).scan("hello Alice")
    assert any(h.kind == "person" and h.value == "Alice" for h in hits)


def test_ner_absent_is_none(monkeypatch):
    monkeypatch.setattr(importlib.util, "find_spec", lambda name, *a, **k: None)
    assert load_presidio() is None


def test_presidio_model_absent_builds_nothing(monkeypatch):
    built = []
    mod = types.ModuleType("presidio_analyzer")

    class AnalyzerEngine:
        def __init__(self, *a, **k):
            built.append(1)

    mod.AnalyzerEngine = AnalyzerEngine
    sub = types.ModuleType("presidio_analyzer.nlp_engine")

    class NlpEngineProvider:
        def __init__(self, *a, **k):
            built.append(1)

    sub.NlpEngineProvider = NlpEngineProvider
    monkeypatch.setitem(sys.modules, "presidio_analyzer", mod)
    monkeypatch.setitem(sys.modules, "presidio_analyzer.nlp_engine", sub)
    real = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name, *a, **k: None if name == "en_core_web_sm" else object(),
    )
    assert load_presidio() is None
    assert built == []
    monkeypatch.setattr(importlib.util, "find_spec", real)
