"""Core model: actions, trust levels, detection classes and hits."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum


class Action(IntEnum):
    """Policy decision, ordered from least to most restrictive."""

    ALLOW = 0
    PSEUDONYMIZE = 1
    BLOCK = 2
    BLOCK_HARD = 3

    @classmethod
    def parse(cls, s: str) -> Action:
        try:
            return _ACTION_NAMES[s]
        except KeyError:
            raise ValueError(f"unknown action: {s!r}") from None


_ACTION_NAMES: dict[str, Action] = {
    "allow": Action.ALLOW,
    "pseudonymize": Action.PSEUDONYMIZE,
    "block": Action.BLOCK,
    "block-hard": Action.BLOCK_HARD,
}


class Trust(StrEnum):
    LOCAL = "local"
    APPROVED = "approved"
    PUBLIC = "public"


class DetClass(StrEnum):
    CLASSIFIED_MARKING = "classified-marking"
    CUI_MARKING = "cui-marking"
    CONTROLLED_CONTENT = "controlled-content"
    SECRET = "secret"  # noqa: S105 -- enum category label, not a credential
    IDENTIFIER = "identifier"
    OPAQUE_CONTENT = "opaque-content"
    UNPARSEABLE = "unparseable"


@dataclass(frozen=True)
class Hit:
    """A single detection. `kind` selects the placeholder format."""

    rule_id: str
    cls: DetClass
    start: int
    end: int
    value: str
    kind: str | None = None
    verified: bool = True
