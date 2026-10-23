"""In-memory, session-scoped store of pending and granted overrides."""

from __future__ import annotations

import secrets
import threading
from dataclasses import replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cui_guard.pipeline import BlockInfo


class OverrideStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[str, BlockInfo] = {}
        self._granted: set[tuple[str, str]] = set()
        self._justifications: dict[tuple[str, str], str] = {}

    def register(self, block: BlockInfo) -> str:
        override_id = secrets.token_hex(8)
        with self._lock:
            self._pending[override_id] = replace(block, override_id=override_id)
        return override_id

    def grant(self, override_id: str, justification: str) -> BlockInfo:
        """Grant the (content hash, rule) pair behind a pending ID. Raises KeyError if unknown."""
        with self._lock:
            block = self._pending[override_id]
            key = (block.content_hash, block.rule_id)
            self._granted.add(key)
            self._justifications[key] = justification
            return block

    def is_granted(self, content_hash: str, rule_id: str) -> bool:
        with self._lock:
            return (content_hash, rule_id) in self._granted

    def pending(self, override_id: str) -> BlockInfo | None:
        with self._lock:
            return self._pending.get(override_id)
