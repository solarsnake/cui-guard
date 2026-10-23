"""Server-sent events codec."""

from __future__ import annotations

import codecs
import re
from dataclasses import dataclass

_EOL = re.compile(r"\r\n|\r|\n")


@dataclass
class SSEEvent:
    event: str | None
    data: str


class SSEDecoder:
    def __init__(self) -> None:
        self._dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._buf = ""
        self._event: str | None = None
        self._data: list[str] = []

    def _line(self, line: str, out: list[SSEEvent]) -> None:
        if line == "":
            if self._data:
                out.append(SSEEvent(self._event, "\n".join(self._data)))
            self._event = None
            self._data = []
            return
        if line.startswith(":"):
            return
        name, sep, value = line.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        if name == "event":
            self._event = value
        elif name == "data":
            self._data.append(value)

    def _drain(self, final: bool) -> list[SSEEvent]:
        out: list[SSEEvent] = []
        pos = 0
        while True:
            m = _EOL.search(self._buf, pos)
            if m is None:
                break
            if m.group(0) == "\r" and m.end() == len(self._buf) and not final:
                break  # a following \n may still arrive
            self._line(self._buf[pos : m.start()], out)
            pos = m.end()
        self._buf = self._buf[pos:]
        return out

    def feed(self, chunk: bytes) -> list[SSEEvent]:
        self._buf += self._dec.decode(chunk)
        return self._drain(final=False)

    def close(self) -> list[SSEEvent]:
        self._buf += self._dec.decode(b"", final=True)
        out = self._drain(final=True)
        if self._buf:
            self._line(self._buf, out)
            self._buf = ""
        if self._data:
            out.append(SSEEvent(self._event, "\n".join(self._data)))
        self._event = None
        self._data = []
        return out


def encode_event(ev: SSEEvent) -> bytes:
    parts: list[str] = []
    if ev.event is not None:
        parts.append(f"event: {ev.event}\n")
    for line in _EOL.split(ev.data):
        parts.append(f"data: {line}\n")
    parts.append("\n")
    return "".join(parts).encode("utf-8")
