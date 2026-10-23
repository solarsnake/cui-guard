"""Detector facade: union of all detection sources, resolved and cached."""

from __future__ import annotations

import hashlib
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


def _resolve_overlaps(hits: list[Hit]) -> list[Hit]:
    """Among placeholder hits (kind set), keep the longest; secret wins.

    Secrets are placed first (longest first) so an identifier that merely
    spans a secret (e.g. user:pw@host read as an email) cannot swallow it.
    """
    placeholder = [h for h in hits if h.kind is not None]
    order = sorted(
        placeholder,
        key=lambda h: (
            h.cls is not DetClass.SECRET,
            -(h.end - h.start),
            h.start,
            h.rule_id,
        ),
    )
    kept: list[Hit] = []
    for h in order:
        if all(h.end <= k.start or h.start >= k.end for k in kept):
            kept.append(h)
    dropped = {id(h) for h in placeholder} - {id(h) for h in kept}
    return [h for h in hits if id(h) not in dropped]


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

    def scan(self, text: str) -> list[Hit]:
        key = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        cached = self._cache.get(key)
        if cached is not None:
            self._cache.move_to_end(key)
            return list(cached)
        hits = self._scan_uncached(text)
        self._cache[key] = tuple(hits)
        if len(self._cache) > CACHE_MAXSIZE:
            self._cache.popitem(last=False)
        return list(hits)

    def _scan_uncached(self, text: str) -> list[Hit]:
        hits = scan_rules(text, self._rules)
        hits += identifier_hits(text, self._identifiers)
        hits += controlled_content_hits(text, self._identifiers)
        if self._ner is not None:
            hits += self._ner.analyze(text)
        hits = _resolve_overlaps(_dedupe(hits))
        return sorted(hits, key=lambda h: (h.start, h.end, h.rule_id))
