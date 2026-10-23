"""Rule loading and scanning (regex marking detectors)."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from importlib import resources

from cui_guard.detect.normalize import normalize
from cui_guard.model import DetClass, Hit

_FLAGS = {"IGNORECASE": re.IGNORECASE, "MULTILINE": re.MULTILINE}


@dataclass(frozen=True)
class Rule:
    id: str
    cls: DetClass
    pattern: re.Pattern[str]
    kind: str | None
    verified: bool
    source: str


def _compile(rule_id: str, regex: str, flag_names: list[str]) -> re.Pattern[str]:
    flags = 0
    for name in flag_names:
        if name not in _FLAGS:
            raise ValueError(f"rule {rule_id}: unknown flag {name!r}")
        flags |= _FLAGS[name]
    try:
        return re.compile(regex, flags)
    except re.error as e:
        raise ValueError(f"rule {rule_id}: invalid regex: {e}") from e


def _parse_class(rule_id: str, value: str) -> DetClass:
    try:
        return DetClass(value)
    except ValueError:
        raise ValueError(f"rule {rule_id}: unknown class {value!r}") from None


def load_builtin_rules() -> list[Rule]:
    rules: list[Rule] = []
    root = resources.files("cui_guard.detect").joinpath("rules")
    for entry in sorted(root.iterdir(), key=lambda p: p.name):
        if not entry.name.endswith(".toml"):
            continue
        data = tomllib.loads(entry.read_text(encoding="utf-8"))
        for r in data.get("rule", []):
            rules.append(
                Rule(
                    id=r["id"],
                    cls=_parse_class(r["id"], r["class"]),
                    pattern=_compile(r["id"], r["regex"], r.get("flags", [])),
                    kind=r.get("kind"),
                    verified=bool(r["verified"]),
                    source=r["source"],
                )
            )
    return rules


def rules_from_patterns(entries: list[dict], origin: str) -> list[Rule]:
    """Build rules from user/org [[patterns]] entries (id, class, regex, kind?)."""
    rules: list[Rule] = []
    for n, e in enumerate(entries):
        for key in ("id", "class", "regex"):
            if not isinstance(e.get(key), str) or not e[key]:
                raise ValueError(f"patterns[{n}]: missing or invalid key {key!r}")
        try:
            rules.append(
                Rule(
                    id=e["id"],
                    cls=_parse_class(e["id"], e["class"]),
                    pattern=_compile(e["id"], e["regex"], []),
                    kind=e.get("kind"),
                    verified=True,
                    source=origin,
                )
            )
        except ValueError as err:
            raise ValueError(f"patterns[{n}]: {err}") from err
    return rules


def scan_rules(text: str, rules: list[Rule]) -> list[Hit]:
    """Run rules on normalized text; hits carry original-text offsets and value."""
    norm, index_map = normalize(text)
    hits: list[Hit] = []
    for rule in rules:
        for m in rule.pattern.finditer(norm):
            if m.end() == m.start():
                continue
            start = index_map[m.start()]
            end = index_map[m.end() - 1] + 1
            hits.append(
                Hit(
                    rule_id=rule.id,
                    cls=rule.cls,
                    start=start,
                    end=end,
                    value=text[start:end],
                    kind=rule.kind,
                    verified=rule.verified,
                )
            )
    return hits
