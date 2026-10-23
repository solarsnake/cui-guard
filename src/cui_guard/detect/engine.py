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


def _merge_pair(a: Hit, b: Hit, text: str) -> Hit | None:
    """Combine two overlapping placeholder hits; None means drop `a` only."""
    win = min(a, b, key=_rank)
    contains_a = a.start <= b.start and b.end <= a.end
    contains_b = b.start <= a.start and a.end <= b.end
    # A lower-priority hit that swallows a secret must not displace it.
    if contains_a and not contains_b and b.cls is DetClass.SECRET and a is not win:
        return b
    if contains_b and not contains_a and a.cls is DetClass.SECRET and b is not win:
        return a
    start, end = min(a.start, b.start), max(a.end, b.end)
    return Hit(
        win.rule_id, win.cls, start, end, text[start:end], win.kind, win.verified
    )


def _resolve_overlaps(hits: list[Hit], text: str) -> list[Hit]:
    """Merge overlapping placeholder hits (kind set); others are untouched.

    Partial overlaps become one hit over the union. Priority picks the
    kind: secret > rule-based identifier > NER. A non-secret hit that
    fully contains a secret is dropped, so the secret keeps its own
    placeholder (e.g. user:pw@host read as an email).
    """
    others = [h for h in hits if h.kind is None]
    work = sorted((h for h in hits if h.kind is not None), key=lambda h: h.start)
    changed = True
    while changed:
        changed = False
        for i in range(len(work)):
            for j in range(i + 1, len(work)):
                a, b = work[i], work[j]
                if a.end <= b.start or b.end <= a.start:
                    continue
                merged = _merge_pair(a, b, text)
                work = [h for k, h in enumerate(work) if k not in (i, j)]
                work.append(merged)
                changed = True
                break
            if changed:
                break
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
