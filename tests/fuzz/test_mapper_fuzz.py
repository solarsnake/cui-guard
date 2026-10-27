"""Mapper round trip and normalization offset-map validity."""

from __future__ import annotations

import itertools

from hypothesis import assume, given
from hypothesis import strategies as st

from cui_guard.detect.normalize import normalize
from cui_guard.model import DetClass, Hit
from cui_guard.pseudo.mapper import PLACEHOLDER_KINDS, SessionMap


@given(st.lists(st.tuples(st.sampled_from(sorted(PLACEHOLDER_KINDS)), st.text(min_size=1, max_size=40)), max_size=8))
def test_pseudonymize_rehydrate_round_trip(pairs):
    # Values are separated by a character that no value contains. Otherwise echo masking turns
    # the separators themselves into placeholders, and adjacent placeholders (which the
    # boundary-aware pattern deliberately does not match) cannot be rehydrated. That case
    # fails safe: the placeholder stays, no real value is exposed.
    sep = next((c for c in " \n|~" if not any(c in v for _, v in pairs)), None)
    assume(sep is not None)
    text, hits = sep, []
    for kind, value in pairs:
        hits.append(Hit("fuzz", DetClass.IDENTIFIER, len(text), len(text) + len(value), value, kind))
        text += value + sep
    smap = SessionMap()
    masked = smap.pseudonymize(text, hits)
    assert smap.rehydrate(masked) == text


@given(st.text(max_size=300))
def test_normalize_offset_map_valid(text):
    norm, imap = normalize(text)
    assert len(imap) == len(norm) + 1  # one entry per char plus the sentinel
    assert imap[-1] == len(text)
    assert all(0 <= i <= len(text) for i in imap)
    assert all(a <= b for a, b in itertools.pairwise(imap))
    assert all(i < len(text) for i in imap[:-1])
