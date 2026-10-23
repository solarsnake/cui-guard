import dataclasses
import statistics
import time

from cui_guard.detect.engine import Detector
from cui_guard.detect.identifiers import IdentifierConfig
from cui_guard.detect.rules import load_builtin_rules
from cui_guard.model import Action, DetClass, Trust
from cui_guard.override.store import OverrideStore
from cui_guard.pipeline import Opaque, Pipeline, RequestView, Segment
from cui_guard.policy.loader import load_builtin_layer
from cui_guard.policy.merge import merge_layers
from cui_guard.pseudo.mapper import SessionMap

POLICY = merge_layers(load_builtin_layer(), None, None)
CUI = "CUI//SP-CTI"


def detector() -> Detector:
    return Detector(load_builtin_rules(), IdentifierConfig())


def make(trust=Trust.PUBLIC, policy=POLICY, det=None, store=None, timeout_s=10.0):
    store = store or OverrideStore()
    pipe = Pipeline(policy, det or detector(), SessionMap(), trust, store, timeout_s)
    return pipe, store


def view(*texts, opaque=(), unparseable=()):
    segs = [Segment(i, f"messages[{i}]", t) for i, t in enumerate(texts)]
    return RequestView(segs, list(opaque), list(unparseable))


def test_public_cui_blocks_with_override_id():
    pipe, store = make()
    d = pipe.evaluate(view(f"hello {CUI} world"))
    assert not d.forward
    b = d.blocked[0]
    assert b.cls == DetClass.CUI_MARKING and b.action == Action.BLOCK
    assert b.override_id is not None
    assert store.pending(b.override_id) is not None
    assert d.hit_counts[b.rule_id] >= 1


def test_classified_block_hard_no_override():
    for trust in Trust:
        pipe, _ = make(trust)
        d = pipe.evaluate(view("x\nSECRET//NOFORN\ny"))
        assert not d.forward
        assert d.blocked[0].action == Action.BLOCK_HARD
        assert d.blocked[0].override_id is None


def test_approved_cui_allowed():
    pipe, _ = make(Trust.APPROVED)
    d = pipe.evaluate(view(f"hello {CUI}"))
    assert d.forward and d.replacements == {}


def test_public_identifier_pseudonymized():
    pipe, _ = make()
    d = pipe.evaluate(view("ok", "connect to db.example.mil now"))
    assert d.forward
    assert list(d.replacements) == [1]
    assert "host-01.cg.invalid" in d.replacements[1]
    assert "db.example.mil" not in d.replacements[1]


def test_secret_pseudonymized_on_local():
    key = "sk-" + "ant-" + "A" * 24
    pipe, _ = make(Trust.LOCAL)
    d = pipe.evaluate(view(f"key {key}"))
    assert d.forward
    assert key not in d.replacements[0]


def test_image_replaced_on_public_allowed_on_local():
    v = view("hi", opaque=[Opaque(0, "messages[0].content[1] image", "image")])
    d = make(Trust.PUBLIC)[0].evaluate(v)
    assert d.forward and d.replace_opaque == {0}
    d = make(Trust.LOCAL)[0].evaluate(v)
    assert d.forward and d.replace_opaque == set()


def test_server_tool_stripped_not_blocked():
    v = view("hi", opaque=[Opaque(0, "loc", "server_tool")])
    for trust in (Trust.PUBLIC, Trust.APPROVED):
        d = make(trust)[0].evaluate(v)
        assert d.forward and d.replace_opaque == {0}


def test_local_lane_server_tool_allowed():
    v = view("hi", opaque=[Opaque(0, "loc", "server_tool")])
    d = make(Trust.LOCAL)[0].evaluate(v)
    assert d.forward and d.replace_opaque == set()


def test_unparseable_blocks_hard():
    d = make()[0].evaluate(view("hi", unparseable=["messages[2].content[0] weird"]))
    assert not d.forward
    assert d.blocked[0].rule_id == "unparseable"
    assert d.blocked[0].action == Action.BLOCK_HARD


def test_override_grant_unblocks_same_content_only():
    pipe, store = make()
    text = f"a {CUI} b"
    d = pipe.evaluate(view(text))
    store.grant(d.blocked[0].override_id, "approved by owner")
    assert pipe.evaluate(view(text)).forward
    assert not pipe.evaluate(view(text + " more")).forward


def test_overrides_disabled_no_id():
    policy = dataclasses.replace(POLICY, overrides_enabled=False)
    d = make(policy=policy)[0].evaluate(view(f"a {CUI}"))
    assert not d.forward and d.blocked[0].override_id is None


def test_override_disabled_rule_no_id():
    rule = make()[0].evaluate(view(f"a {CUI}")).blocked[0].rule_id
    policy = dataclasses.replace(POLICY, override_disabled_rules=frozenset({rule}))
    d = make(policy=policy)[0].evaluate(view(f"a {CUI}"))
    assert d.blocked[0].override_id is None


class Boom:
    def scan(self, text):
        raise RuntimeError("boom")


class Slow:
    def scan(self, text):
        time.sleep(1.0)
        return []


def test_detector_exception_fails_closed():
    d = make(det=Boom())[0].evaluate(view("a", "b"))
    assert len(d.blocked) == 1
    b = d.blocked[0]
    assert b.rule_id == "internal.error"
    assert b.cls == DetClass.UNPARSEABLE and b.action == Action.BLOCK_HARD


def test_detection_timeout_fails_closed():
    d = make(det=Slow(), timeout_s=0.05)[0].evaluate(view("a"))
    assert [b.rule_id for b in d.blocked] == ["internal.error"]
    assert d.blocked[0].action == Action.BLOCK_HARD


def test_excerpt_masks_match():
    text = "line one\n" + "x" * 200 + f" {CUI} " + "y" * 200
    b = make()[0].evaluate(view(text)).blocked[0]
    assert CUI not in b.excerpt
    assert "█" * len(CUI) in b.excerpt
    assert len(b.excerpt) <= 120
    assert "\n" not in b.excerpt


def test_cached_history_latency_budget():
    pipe, _ = make()
    chunk = (
        "def handler(request):\n    return render(request, 'index.html')\n"
        "Meeting notes: discuss the roadmap and ship the release on Friday. "
    )
    history = [(chunk * 40)[:5000] + f" turn {i}" for i in range(400)]
    assert sum(map(len, history)) >= 1_900_000
    assert pipe.evaluate(view(*history)).forward
    times = []
    for n in range(50):
        t0 = time.perf_counter()
        pipe.evaluate(view(*history, f"new message number {n}"))
        times.append(time.perf_counter() - t0)
    p95 = statistics.quantiles(times, n=20)[-1]
    assert p95 <= 0.050, p95


def test_timed_out_worker_mutates_nothing():
    from cui_guard.model import Hit

    class SlowHits:
        def scan(self, text):
            time.sleep(0.3)
            return [Hit("cui.test", DetClass.CUI_MARKING, 0, 3, text[:3], "term")]

    store = OverrideStore()
    smap = SessionMap()
    pipe = Pipeline(POLICY, SlowHits(), smap, Trust.PUBLIC, store, 0.05)
    d = pipe.evaluate(view("abcdef", "ghijkl"))
    assert [b.rule_id for b in d.blocked] == ["internal.error"]
    time.sleep(0.8)  # let the worker finish
    assert len(smap) == 0
    assert store._pending == {}
    assert pipe._unchanged == set()


def test_unchanged_cache_invalidated_when_map_grows():
    pipe, _ = make()
    # Segment B has an ordinary word; it is not detected, so it is cached as unchanged.
    d = pipe.evaluate(view("plain words only"))
    assert d.replacements == {}
    pipe.evaluate(view("plain words only"))  # cached path
    # A later request maps "plain" via a hit; echo re-mask must now apply to the old segment.
    from cui_guard.model import Hit

    class OneHit:
        def scan(self, text):
            i = text.find("plain")
            if text.startswith("map ") and i >= 0:
                return [Hit("t.id", DetClass.IDENTIFIER, i, i + 5, "plain", "term")]
            return []

    pipe2 = Pipeline(POLICY, OneHit(), pipe._smap, Trust.PUBLIC, OverrideStore())
    pipe2._unchanged = pipe._unchanged
    assert pipe2.evaluate(view("plain words only")).replacements == {}
    assert pipe2.evaluate(view("map plain")).replacements == {0: "map CG_TERM_01"}
    d = pipe2.evaluate(view("plain words only"))
    assert d.replacements == {0: "CG_TERM_01 words only"}


def test_pseudonymize_hit_without_kind_blocks():
    from cui_guard.model import Hit

    class NoKind:
        def scan(self, text):
            return [Hit("t.nokind", DetClass.SECRET, 0, 3, text[:3], None)]

    d = make(det=NoKind())[0].evaluate(view("abcdef"))
    assert not d.forward
    assert d.blocked[0].action == Action.BLOCK
    assert d.blocked[0].override_id is not None


def test_url_source_and_encrypted_replaced_on_public():
    v = view("hi", opaque=[Opaque(0, "a", "url_source"), Opaque(1, "b", "encrypted")])
    d = make(Trust.PUBLIC)[0].evaluate(v)
    assert d.forward and d.replace_opaque == {0, 1}


def test_image_untouched_on_approved():
    v = view("hi", opaque=[Opaque(0, "a", "image")])
    d = make(Trust.APPROVED)[0].evaluate(v)
    assert d.forward and d.replace_opaque == set()


def test_block_and_replacements_together():
    d = make()[0].evaluate(view(f"{CUI} here", "connect to db.example.mil"))
    assert not d.forward
    assert 1 in d.replacements and "host-01.cg.invalid" in d.replacements[1]
