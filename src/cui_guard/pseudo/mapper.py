"""Session map: reversible placeholders for sensitive values."""

from __future__ import annotations

import re
import threading

from cui_guard.model import Hit

_IP_MAX = 65534

# Boundary-aware: a token never matches inside a longer identifier or number.
PLACEHOLDER_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"host-\d+\.cg\.invalid"
    r"|person\d+@example\.invalid"
    r"|CGTKT-\d+"
    r"|CG_(?:PERSON|SECRET|TERM)_\d+"
    r")(?![A-Za-z0-9_])"
    r"|(?<![A-Za-z0-9_])(?<!\d\.)198\.18\.\d{1,3}\.\d{1,3}(?![A-Za-z0-9_])(?!\.\d)"
)

_FORMATS = {
    "host": lambda n: f"host-{n:02d}.cg.invalid",
    "ip": lambda n: f"198.18.{n // 256}.{n % 256}",
    "email": lambda n: f"person{n:02d}@example.invalid",
    "jira": lambda n: f"CGTKT-{n}",
    "person": lambda n: f"CG_PERSON_{n:02d}",
    "secret": lambda n: f"CG_SECRET_{n:02d}",
    "term": lambda n: f"CG_TERM_{n:02d}",
}
PLACEHOLDER_KINDS = frozenset(_FORMATS)


class SessionMap:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._fwd: dict[tuple[str, str], str] = {}
        self._rev: dict[str, str] = {}
        self._echo: dict[str, str] = {}  # real value -> placeholder
        self._echo_re: re.Pattern[str] | None = None
        self._counters: dict[str, int] = {}
        self._seen: set[str] = set()

    def __len__(self) -> int:
        with self._lock:
            return len(self._fwd)

    def _record(self, text: str) -> None:
        self._seen.update(m.group(0) for m in PLACEHOLDER_RE.finditer(text))

    def _assign(self, value: str, kind: str) -> str:
        if kind not in _FORMATS:
            raise ValueError(f"unknown placeholder kind: {kind!r}")
        if not value:
            raise ValueError("cannot map an empty value")
        key = (kind, value)
        found = self._fwd.get(key)
        if found is not None:
            return found
        fmt = _FORMATS[kind]
        n = self._counters.get(kind, 0)
        while True:
            n += 1
            if kind == "ip" and n > _IP_MAX:
                raise RuntimeError("ip placeholder space exhausted")
            cand = fmt(n)
            if cand not in self._seen and cand not in self._rev:
                break
        self._counters[kind] = n
        self._fwd[key] = cand
        self._rev[cand] = value
        if value not in self._echo:
            self._echo[value] = cand
            self._echo_re = None
        return cand

    def placeholder_for(self, value: str, kind: str) -> str:
        with self._lock:
            return self._assign(value, kind)

    def pseudonymize(self, text: str, hits: list[Hit]) -> str:
        with self._lock:
            self._record(text)
            out: list[str] = []
            pos = 0
            for h in sorted(hits, key=lambda h: (h.start, h.end)):
                if h.kind is None or h.start < pos or h.end <= h.start:
                    continue
                out.append(text[pos : h.start])
                out.append(self._assign(text[h.start : h.end], h.kind))
                pos = h.end
            out.append(text[pos:])
            return self._remask("".join(out))

    def _remask(self, text: str) -> str:
        if not self._echo:
            return text
        if self._echo_re is None:
            vals = sorted(self._echo, key=len, reverse=True)
            self._echo_re = re.compile("|".join(re.escape(v) for v in vals))
        pattern = self._echo_re
        out: list[str] = []
        pos = 0
        for m in PLACEHOLDER_RE.finditer(text):
            out.append(pattern.sub(lambda x: self._echo[x.group(0)], text[pos : m.start()]))
            out.append(m.group(0))
            pos = m.end()
        out.append(pattern.sub(lambda x: self._echo[x.group(0)], text[pos:]))
        return "".join(out)

    def rehydrate(self, text: str) -> str:
        with self._lock:
            self._record(text)
            return PLACEHOLDER_RE.sub(lambda m: self._rev.get(m.group(0), m.group(0)), text)

    def leftover_placeholders(self, text: str) -> list[str]:
        with self._lock:
            return [m.group(0) for m in PLACEHOLDER_RE.finditer(text) if m.group(0) not in self._rev]
