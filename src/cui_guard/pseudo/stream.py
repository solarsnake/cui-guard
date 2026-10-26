"""Streaming helpers: rehydrate placeholders split across chunks or JSON fragments."""

from __future__ import annotations

import json
import re
from typing import Any

from cui_guard.pseudo.mapper import PLACEHOLDER_RE, SessionMap

# Upper bound on how many trailing characters are ever held back.
MAX_HOLD = 40
_CTX = 2  # chars of already-emitted text kept so lookbehinds see real context

_LIT = "lit"
_DIG = "dig"


def _gen(items: list[tuple[str, str]]) -> str:
    """Regex matching any prefix (including complete) of the item template, up to end."""
    if not items:
        return r"\Z"
    kind, val = items[0]
    rest = items[1:]
    if kind == _LIT:
        alts = [re.escape(val[:k]) + r"\Z" for k in range(len(val))]
        alts.append(re.escape(val) + _gen(rest))
        return "(?:" + "|".join(alts) + ")"
    return r"(?:\Z|\d{1," + val + "}" + _gen(rest) + ")"


def _lit(s: str) -> tuple[str, str]:
    return (_LIT, s)


def _dig(n: str = "9") -> tuple[str, str]:
    return (_DIG, n)


_TEMPLATES = [
    [_lit("host-"), _dig("30"), _lit(".cg.invalid")],
    [_lit("person"), _dig("30"), _lit("@example.invalid")],
    [_lit("CGTKT-"), _dig("30")],
    [_lit("CG_PERSON_"), _dig("30")],
    [_lit("CG_SECRET_"), _dig("30")],
    [_lit("CG_TERM_"), _dig("30")],
    [_lit("CG_")],
]
_IP_TEMPLATE = [_lit("198.18."), _dig("3"), _lit("."), _dig("3"), _lit(".")]

_VIABLE = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    + "|".join(_gen(t) for t in _TEMPLATES)
    + r")|(?<![A-Za-z0-9_])(?<!\d\.)"
    + _gen(_IP_TEMPLATE)
)


class TextHoldback:
    """Rehydrate streamed text, holding back a trailing suffix that may grow into a placeholder."""

    def __init__(self, smap: SessionMap) -> None:
        self._smap = smap
        self._ctx = ""
        self._pending = ""

    def _convert(self, s: str, start: int, end: int) -> str:
        out: list[str] = []
        pos = start
        for m in PLACEHOLDER_RE.finditer(s, start, end):
            out.append(s[pos : m.start()])
            out.append(self._smap.rehydrate(m.group(0)))
            pos = m.end()
        out.append(s[pos:end])
        return "".join(out)

    def feed(self, chunk: str) -> str:
        s = self._ctx + self._pending + chunk
        off = len(self._ctx)
        cut = len(s)
        for i in range(max(off, len(s) - MAX_HOLD), len(s)):
            if _VIABLE.match(s, i):
                cut = i
                break
        out = self._convert(s, off, cut)
        self._ctx = s[max(0, cut - _CTX) : cut]
        self._pending = s[cut:]
        return out

    def flush(self) -> str:
        s = self._ctx + self._pending
        out = self._convert(s, len(self._ctx), len(s))
        self._ctx = ""
        self._pending = ""
        return out


def _walk(obj: Any, smap: SessionMap) -> Any:
    if isinstance(obj, str):
        return smap.rehydrate(obj)
    if isinstance(obj, list):
        return [_walk(v, smap) for v in obj]
    if isinstance(obj, dict):
        # Keys are never scanned outbound, so they are never rehydrated.
        return {k: _walk(v, smap) for k, v in obj.items()}
    return obj


def rehydrate_json_text(json_text: str, smap: SessionMap) -> str:
    """Rehydrate every string value (never keys) of a JSON document; raises ValueError if invalid."""
    obj = json.loads(json_text)  # JSONDecodeError is a ValueError
    return json.dumps(_walk(obj, smap), ensure_ascii=False, separators=(",", ":"))


class ArgsBuffer:
    """Accumulates tool-call argument JSON fragments until the call is complete."""

    def __init__(self) -> None:
        self._parts: list[str] = []

    def feed(self, fragment: str) -> None:
        self._parts.append(fragment)

    def finish(self, smap: SessionMap) -> str:
        return rehydrate_json_text("".join(self._parts), smap)
