"""Decision pipeline: detect, decide, transform. Never raises; fails closed."""

from __future__ import annotations

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from cui_guard.detect.engine import Detector
from cui_guard.model import Action, DetClass, Hit, Trust
from cui_guard.override.store import OverrideStore
from cui_guard.policy.schema import EffectivePolicy
from cui_guard.pseudo.mapper import SessionMap

EXCERPT_CHARS = 120
_UNCHANGED_MAX = 20000
MASK = "█"
_ALWAYS_BLOCKED_OPAQUE = frozenset({"server_tool", "url_source", "encrypted"})
THINKING_RULE = "history.thinking_sensitive"
THINKING_MESSAGE = (
    "the conversation history holds sensitive model reasoning (thinking) that cannot be "
    "rewritten without breaking its signatures; start a fresh session"
)
_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="cui-guard-detect")


@dataclass
class Segment:
    index: int
    location: str
    text: str


@dataclass
class Opaque:
    index: int
    location: str
    kind: str  # image | document | server_tool | url_source | encrypted


@dataclass
class RequestView:
    segments: list[Segment]
    opaque: list[Opaque]
    unparseable: list[str]  # locations of unknown types
    # Scanned but never rewritten (signed thinking, reasoning summaries).
    readonly: list[Segment] = field(default_factory=list)


@dataclass
class BlockInfo:
    rule_id: str
    cls: DetClass
    action: Action
    location: str
    excerpt: str
    content_hash: str
    override_id: str | None


@dataclass
class Decision:
    blocked: list[BlockInfo] = field(default_factory=list)
    replacements: dict[int, str] = field(default_factory=dict)
    replace_opaque: set[int] = field(default_factory=set)
    hit_counts: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def forward(self) -> bool:
        return not self.blocked


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def make_excerpt(text: str, hit: Hit, all_hits: list[Hit]) -> str:
    """At most 120 chars around the match; every detected span is masked, newlines become spaces."""
    length = max(hit.end - hit.start, 0)
    pad = max((EXCERPT_CHARS - length) // 2, 0)
    lo = max(hit.start - pad, 0)
    hi = min(hit.end + pad, len(text), lo + EXCERPT_CHARS)
    chars = list(text[lo:hi])
    for h in [*all_hits, hit]:
        for i in range(max(h.start, lo), min(h.end, hi)):
            chars[i - lo] = MASK
    return "".join(chars).replace("\r", " ").replace("\n", " ")[:EXCERPT_CHARS]


class Pipeline:
    def __init__(
        self,
        policy: EffectivePolicy,
        detector: Detector,
        smap: SessionMap,
        trust: Trust,
        overrides: OverrideStore,
        timeout_s: float = 10.0,
    ) -> None:
        self._policy = policy
        self._detector = detector
        self._smap = smap
        self._trust = trust
        self._overrides = overrides
        self._timeout_s = timeout_s
        # (text digest, session map size) of segments the echo re-mask left unchanged.
        # The re-mask depends only on the map's contents, which only grow.
        self._unchanged: set[tuple[str, int]] = set()
        self._unchanged_lock = threading.Lock()

    def evaluate(self, view: RequestView) -> Decision:
        try:
            # The worker runs pure detection only; every decision and mutation
            # happens here, so a timed-out worker can change nothing.
            texts = [s.text for s in view.segments] + [s.text for s in view.readonly]
            future = _EXECUTOR.submit(self._scan_all, texts)
            all_hits = future.result(timeout=self._timeout_s)
            n = len(view.segments)
            return self._evaluate(view, all_hits[:n], all_hits[n:])
        except Exception as e:  # noqa: BLE001 - fail closed on anything, incl. timeout
            return self._internal_error(type(e).__name__)

    @staticmethod
    def _internal_error(why: str) -> Decision:
        block = BlockInfo(
            "internal.error", DetClass.UNPARSEABLE, Action.BLOCK_HARD,
            "request", f"evaluation failed: {why}", _sha256("internal.error"), None,
        )  # fmt: skip
        return Decision(blocked=[block], hit_counts={"internal.error": 1})

    def _scan_all(self, texts: list[str]) -> list[list[Hit]]:
        return [self._detector.scan(t) for t in texts]

    def _evaluate(
        self, view: RequestView, all_hits: list[list[Hit]], ro_hits: list[list[Hit]]
    ) -> Decision:
        d = Decision()
        for loc in view.unparseable:
            self._add_block(d, "unparseable", DetClass.UNPARSEABLE, Action.BLOCK_HARD,
                            loc, "unknown content type", _sha256(loc))  # fmt: skip
        for seg, hits in zip(view.segments, all_hits, strict=True):
            self._segment(d, seg, hits)
        for seg, hits in zip(view.readonly, ro_hits, strict=True):
            self._readonly(d, seg, hits)
        for op in view.opaque:
            self._opaque(d, op)
        return d

    @staticmethod
    def _add_block(d, rule_id, cls, action, location, excerpt, content_hash, override_id=None):
        d.blocked.append(
            BlockInfo(rule_id, cls, action, location, excerpt, content_hash, override_id)
        )
        d.hit_counts[rule_id] = d.hit_counts.get(rule_id, 0) + 1

    def _segment(self, d: Decision, seg: Segment, hits: list[Hit]) -> None:
        digest = _sha256(seg.text)
        to_mask: list[Hit] = []
        for hit in hits:
            action = self._policy.action_for(hit, self._trust)
            if action == Action.ALLOW:
                d.hit_counts[hit.rule_id] = d.hit_counts.get(hit.rule_id, 0) + 1
                continue
            if action == Action.PSEUDONYMIZE and hit.kind is not None:
                d.hit_counts[hit.rule_id] = d.hit_counts.get(hit.rule_id, 0) + 1
                to_mask.append(hit)
                continue
            if action == Action.PSEUDONYMIZE:
                action = Action.BLOCK  # cannot mask a hit without a placeholder kind
            if action == Action.BLOCK and self._overrides.is_granted(digest, hit.rule_id):
                d.hit_counts[hit.rule_id] = d.hit_counts.get(hit.rule_id, 0) + 1
                continue
            info = BlockInfo(
                hit.rule_id, hit.cls, action, seg.location,
                make_excerpt(seg.text, hit, hits), digest, None,
            )  # fmt: skip
            if (
                action == Action.BLOCK
                and self._policy.overrides_enabled
                and hit.rule_id not in self._policy.override_disabled_rules
            ):
                info.override_id = self._overrides.register(info)
            d.blocked.append(info)
            d.hit_counts[hit.rule_id] = d.hit_counts.get(hit.rule_id, 0) + 1
        size = len(self._smap)
        key = (digest, size)
        if not to_mask:
            with self._unchanged_lock:
                if key in self._unchanged:
                    return
        new_text = self._smap.pseudonymize(seg.text, to_mask)
        if new_text != seg.text:
            d.replacements[seg.index] = new_text
        elif not to_mask and len(self._smap) == size:
            # Re-checked after the re-mask: if another request grew the map meanwhile,
            # this result is not cached, so the next request re-masks against the new values.
            with self._unchanged_lock:
                if len(self._unchanged) >= _UNCHANGED_MAX:
                    self._unchanged.clear()
                self._unchanged.add(key)

    def _readonly(self, d: Decision, seg: Segment, hits: list[Hit]) -> None:
        """Text that cannot be rewritten: anything the lane would mask or block stops the request."""
        for hit in hits:
            if self._policy.action_for(hit, self._trust) >= Action.PSEUDONYMIZE:
                self._add_block(d, THINKING_RULE, hit.cls, Action.BLOCK_HARD, seg.location,
                                f"{THINKING_MESSAGE} (matched {hit.rule_id})",
                                _sha256(seg.text))  # fmt: skip
                return

    def _opaque(self, d: Decision, op: Opaque) -> None:
        forced = op.kind in _ALWAYS_BLOCKED_OPAQUE and self._trust != Trust.LOCAL
        if not forced:
            action = self._policy.action_for_class(DetClass.OPAQUE_CONTENT, self._trust)
            if action == Action.ALLOW:
                return
        d.replace_opaque.add(op.index)
        d.hit_counts["opaque-content"] = d.hit_counts.get("opaque-content", 0) + 1
