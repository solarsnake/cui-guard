"""Detector facade: union of all detection sources, resolved and cached."""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict

from cui_guard.detect.heuristics import controlled_content_hits
from cui_guard.detect.identifiers import IdentifierConfig, identifier_hits
from cui_guard.detect.ner import NerBackend
from cui_guard.detect.rules import Rule, scan_rules
from cui_guard.model import DetClass, Hit

CACHE_MAXSIZE = 50_000


def _dedupe(hits: list[Hit]) -> list[Hit]:
    best: dict[tuple[int, int, DetClass], Hit] = {}
    for h in hits:
        key = (h.start, h.end, h.cls)
        cur = best.get(key)
        if cur is None or (not h.verified, h.rule_id) < (not cur.verified, cur.rule_id):
            best[key] = h
    return list(best.values())


def _priority(h: Hit) -> int:
    if h.cls is DetClass.SECRET:
        return 0
    return 2 if h.rule_id.startswith("ner.") else 1


def _rank(h: Hit) -> tuple[int, int, str]:
    return (_priority(h), -(h.end - h.start), h.rule_id)


def _merge_pair(a: Hit, b: Hit, text: str) -> tuple[Hit, Hit | None]:
    """Combine two overlapping placeholder hits into (kept, dropped container)."""
    win = min(a, b, key=_rank)
    contains_a = a.start <= b.start and b.end <= a.end
    contains_b = b.start <= a.start and a.end <= b.end
    # A lower-priority hit that swallows a secret must not displace it.
    if contains_a and not contains_b and b.cls is DetClass.SECRET and a is not win:
        return b, a
    if contains_b and not contains_a and a.cls is DetClass.SECRET and b is not win:
        return a, b
    start, end = min(a.start, b.start), max(a.end, b.end)
    merged = Hit(
        win.rule_id, win.cls, start, end, text[start:end], win.kind, win.verified
    )
    return merged, None


def _remainders(container: Hit, kept: list[Hit], text: str) -> list[Hit]:
    """Sub-spans of a dropped container not covered by kept hits (alnum only)."""
    pieces: list[Hit] = []
    pos = container.start
    covers = sorted(
        (k for k in kept if k.start < container.end and k.end > container.start),
        key=lambda k: k.start,
    )
    for k in [*covers, None]:
        stop = container.end if k is None else min(k.start, container.end)
        if stop > pos and any(c.isalnum() for c in text[pos:stop]):
            pieces.append(
                Hit(
                    container.rule_id,
                    container.cls,
                    pos,
                    stop,
                    text[pos:stop],
                    container.kind,
                    container.verified,
                )
            )
        if k is not None:
            pos = max(pos, k.end)
    return pieces


def _resolve_overlaps(hits: list[Hit], text: str) -> list[Hit]:
    """Merge overlapping placeholder hits (kind set); others are untouched.

    Partial overlaps become one hit over the union. Priority picks the
    kind: secret > rule-based identifier > NER. A non-secret hit that
    fully contains a secret is split: the secret keeps its own
    placeholder (e.g. user:pw@host read as an email) and the container's
    uncovered remainder pieces that hold alphanumerics stay masked.

    Sweep line over hits sorted by (start, -end). Kept hits stay disjoint
    and ordered, so a new hit can only overlap the last kept one.
    """
    others = [h for h in hits if h.kind is None]
    ordered = sorted(
        (h for h in hits if h.kind is not None), key=lambda h: (h.start, -h.end, _rank(h))
    )
    work: list[Hit] = []
    dropped: list[Hit] = []
    for h in ordered:
        if not work or work[-1].end <= h.start:
            work.append(h)
            continue
        kept, drop = _merge_pair(work[-1], h, text)
        work[-1] = kept
        if drop is not None:
            dropped.append(drop)
    pieces = [p for d in dropped for p in _remainders(d, work, text)]
    if pieces:
        work += _resolve_overlaps(pieces, text)
    return others + work


class Detector:
    def __init__(
        self,
        rules: list[Rule],
        identifiers: IdentifierConfig,
        ner: NerBackend | None = None,
    ) -> None:
        self._rules = rules
        self._identifiers = identifiers
        self._ner = ner
        self._cache: OrderedDict[str, tuple[Hit, ...]] = OrderedDict()
        self._lock = threading.Lock()

    def scan(self, text: str) -> list[Hit]:
        key = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                self._cache.move_to_end(key)
                return list(cached)
        hits = self._scan_uncached(text)
        with self._lock:
            self._cache[key] = tuple(hits)
            self._cache.move_to_end(key)
            while len(self._cache) > CACHE_MAXSIZE:
                self._cache.popitem(last=False)
        return list(hits)

    def _scan_uncached(self, text: str) -> list[Hit]:
        hits = scan_rules(text, self._rules)
        hits += identifier_hits(text, self._identifiers)
        hits += controlled_content_hits(text, self._identifiers)
        if self._ner is not None:
            hits += self._ner.analyze(text)
        hits = _resolve_overlaps(_dedupe(hits), text)
        return sorted(hits, key=lambda h: (h.start, h.end, h.rule_id))
