"""Provider adapter protocols."""

from __future__ import annotations

from typing import Protocol

from cui_guard.adapters.sse import SSEEvent
from cui_guard.pipeline import Decision, RequestView
from cui_guard.pseudo.mapper import SessionMap


class StreamRewriter(Protocol):
    notes: list[str]

    @property
    def pending(self) -> bool:
        """True while output is held back (text hold-back or buffered tool arguments)."""
        ...

    def feed(self, ev: SSEEvent) -> list[SSEEvent]: ...

    def finish(self) -> list[SSEEvent]: ...


class Adapter(Protocol):
    format: str
    paths: tuple[str, ...]
    block_status: int

    def extract(self, body: dict) -> RequestView: ...

    def apply(self, body: dict, decision: Decision) -> dict: ...

    def rehydrate_response(self, body: dict, smap: SessionMap) -> dict: ...

    def stream_rewriter(self, smap: SessionMap) -> StreamRewriter: ...

    def keepalive(self) -> SSEEvent | bytes: ...

    def error_body(self, message: str) -> dict: ...
