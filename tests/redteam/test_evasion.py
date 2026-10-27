"""Detection-evasion corpus: obfuscated canaries against the real gateway (public lane).

Every (transform, kind) pair is CAUGHT unless pinned KNOWN_GAP in EXPECTED. Known gaps are
strict xfails, so a detector fix flips the test: update EXPECTED and docs/LIMITS.md then.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from canaries import CANARIES, PATHS, build, carrier

from .transforms import (
    BUILDER_TRANSFORMS,
    EXPECTED,
    NEEDLE_TRANSFORMS,
    SPLIT,
    TRANSFORMS,
    halves,
)

ROOT = Path(__file__).resolve().parents[2]
CANARY_KINDS = sorted(CANARIES)


def _jsonish(s: str) -> list[str]:
    """A string as it can appear in a JSON body: raw, ASCII-escaped, and UTF-8."""
    return [s, json.dumps(s)[1:-1], json.dumps(s, ensure_ascii=False)[1:-1]]


def build_request(
    fmt: str, transform: str, kind: str
) -> tuple[dict | bytes, list[tuple[str, ...]]]:
    """The request, plus the leak signatures: any signature fully present means leaked."""
    needle = CANARIES[kind]
    fn = TRANSFORMS[transform]
    if transform in NEEDLE_TRANSFORMS:
        obf = fn(needle)
        body = build(fmt, "user", carrier(kind).replace(needle, obf), False)
        sigs = [(f,) for f in _jsonish(needle) + _jsonish(obf)]
    elif transform == "json_in_string":
        body = build(fmt, "user", fn(carrier(kind)), False)
        sigs = [(f,) for f in _jsonish(needle)]
    elif transform == "json_u_escape":
        raw = json.dumps(build(fmt, "user", carrier(kind), False))
        body = fn(raw).encode()
        sigs = [(f,) for f in _jsonish(needle)]
    elif transform in SPLIT:
        body = fn(needle, fmt)
        a, b = halves(needle)
        sigs = [(f, g) for f, g in zip(_jsonish(a), _jsonish(b), strict=True)]
    else:
        # The Nessus canary is only detectable inside its export, so carry it whole.
        body = fn(carrier(kind) if kind == "controlled" else needle, fmt)
        sigs = [(f,) for f in _jsonish(needle)]
    return body, sigs


def send_and_check(gateways, upstream, fmt, transform, kind) -> bool:
    """True if the raw canary or its transformed form reached the upstream."""
    body, sigs = build_request(fmt, transform, kind)
    upstream.reset()
    gateways("public").post(PATHS[fmt], body)
    sent = upstream.all_bytes().decode("utf-8", "replace")
    return any(all(p in sent for p in sig) for sig in sigs)


def _noop(transform: str, kind: str) -> bool:
    if kind == "controlled" and transform in SPLIT | {"document_title"}:
        return True  # a multi-line export cannot be split or titled meaningfully
    if (
        transform in ("identity", "json_in_string")
        or transform not in NEEDLE_TRANSFORMS
    ):
        return False
    needle = CANARIES[kind]
    return TRANSFORMS[transform](needle) == needle


def _params():
    for transform in sorted(TRANSFORMS):
        for kind in CANARY_KINDS:
            marks = []
            if _noop(transform, kind):
                marks.append(
                    pytest.mark.skip(
                        reason=f"{transform} does not apply to a {kind} canary"
                    )
                )
            elif EXPECTED.get((transform, kind), "CAUGHT") == "KNOWN_GAP":
                marks.append(
                    pytest.mark.xfail(
                        strict=True, reason=f"known gap: {transform}/{kind}"
                    )
                )
            yield pytest.param(transform, kind, marks=marks, id=f"{transform}-{kind}")


@pytest.mark.parametrize("transform,kind", list(_params()))
def test_evasion(gateways, upstream, fmt, transform, kind):
    leaked = send_and_check(gateways, upstream, fmt, transform, kind)
    assert not leaked, f"{transform}/{kind}/{fmt}: canary reached the upstream"


def test_every_known_gap_is_in_limits():
    limits = (ROOT / "docs/LIMITS.md").read_text()
    section = limits.split("### Known evasion gaps", 1)[1]
    for transform in {t for (t, _), v in EXPECTED.items() if v == "KNOWN_GAP"}:
        assert f"`{transform}`" in section, transform


# Tool-less sanity: BUILDER_TRANSFORMS and TRANSFORMS stay in step.
def test_transform_registry_is_complete():
    assert set(TRANSFORMS) == NEEDLE_TRANSFORMS | BUILDER_TRANSFORMS | {
        "json_in_string",
        "json_u_escape",
    }
    assert len(TRANSFORMS) == 20
