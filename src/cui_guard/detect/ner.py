"""Optional NER backend (PERSON entities) built on presidio-analyzer."""

from __future__ import annotations

import importlib.util
from typing import Protocol

from cui_guard.model import DetClass, Hit


class NerBackend(Protocol):
    def analyze(self, text: str) -> list[Hit]: ...


class _PresidioBackend:
    def __init__(self, engine) -> None:
        self._engine = engine

    def analyze(self, text: str) -> list[Hit]:
        results = self._engine.analyze(text=text, entities=["PERSON"], language="en")
        return [
            Hit(
                rule_id="ner.person",
                cls=DetClass.IDENTIFIER,
                start=r.start,
                end=r.end,
                value=text[r.start : r.end],
                kind="person",
            )
            for r in results
            if r.entity_type == "PERSON"
        ]


def load_presidio() -> NerBackend | None:
    """Return a presidio-backed NER, or None if unavailable. Never downloads."""
    try:
        if (
            importlib.util.find_spec("presidio_analyzer") is None
            or importlib.util.find_spec("spacy") is None
        ):
            return None
        from presidio_analyzer import AnalyzerEngine

        return _PresidioBackend(AnalyzerEngine(supported_languages=["en"]))
    except Exception:  # noqa: BLE001
        # Missing spacy model or any other setup failure: NER stays off.
        return None
