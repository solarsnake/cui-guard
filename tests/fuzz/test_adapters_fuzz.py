"""Coverage invariant: no request string leaf is forwarded unscanned."""

from __future__ import annotations

import copy

import pytest
from hypothesis import given

from cui_guard.adapters.anthropic import AnthropicAdapter
from cui_guard.adapters.openai_chat import OpenAIChatAdapter
from cui_guard.adapters.openai_responses import OpenAIResponsesAdapter

from .strategies import FORMATS, request_bodies, string_leaves, untouched

ADAPTERS = {
    "anthropic": AnthropicAdapter(),
    "openai-responses": OpenAIResponsesAdapter(),
    "openai-chat": OpenAIChatAdapter(),
}


@pytest.mark.parametrize("fmt", FORMATS)
def test_coverage_invariant(fmt):
    @given(body=request_bodies(fmt))
    def prop(body):
        view = ADAPTERS[fmt].extract(copy.deepcopy(body))
        if view.unparseable:
            return  # fails closed, which is fine
        scanned = {s.text for s in view.segments} | {s.text for s in view.readonly}
        opaque = tuple(o.location for o in view.opaque)
        for path, leaf in string_leaves(body, fmt):
            if leaf == "":
                continue  # nothing to scan
            assert leaf in scanned or untouched(fmt, path, opaque), path

    prop()


@pytest.mark.parametrize("fmt", FORMATS)
def test_extract_never_raises(fmt):
    @given(body=request_bodies(fmt))
    def prop(body):
        before = copy.deepcopy(body)
        ADAPTERS[fmt].extract(body)  # any exception fails the property
        assert body == before  # extraction never mutates the request

    prop()


# -- regression tests for falsified properties ---------------------------


def test_unhashable_block_type_is_unparseable():
    # A list or dict as a block `type` used to raise TypeError out of extract.
    a = ADAPTERS["anthropic"].extract({"messages": [{"role": "user", "content": [{"type": ["x"]}]}]})
    assert a.unparseable == ["messages[0].content[0]"]
    r = ADAPTERS["openai-responses"].extract({"input": [{"type": {"a": 1}}]})
    assert r.unparseable == ["input[0]"]


def test_non_list_citations_are_unparseable():
    # citations that are not a list used to be skipped, forwarding their text unscanned.
    body = {"messages": [{"role": "user", "content": [{"type": "text", "text": "t", "citations": "CANARY-1"}]}]}
    assert ADAPTERS["anthropic"].extract(body).unparseable == ["messages[0].content[0].citations"]


def test_non_list_annotations_are_unparseable():
    part = {"type": "input_text", "text": "t", "annotations": "CANARY-1"}
    body = {"input": [{"type": "message", "role": "user", "content": [part]}]}
    assert ADAPTERS["openai-responses"].extract(body).unparseable == ["input[0].content[0].annotations"]


# -- unknown keys nested in known containers are scanned -----------------

MARKING = "CUI//SP-CTI"
HOST = "db.example.mil"


def _pipeline():
    from cui_guard.detect.engine import Detector
    from cui_guard.detect.identifiers import IdentifierConfig
    from cui_guard.detect.rules import load_builtin_rules
    from cui_guard.model import Trust
    from cui_guard.override.store import OverrideStore
    from cui_guard.pipeline import Pipeline
    from cui_guard.policy.loader import load_builtin_layer
    from cui_guard.policy.merge import merge_layers
    from cui_guard.pseudo.mapper import SessionMap

    policy = merge_layers(load_builtin_layer(), None, None)
    det = Detector(load_builtin_rules(), IdentifierConfig())
    return Pipeline(policy, det, SessionMap(), Trust.PUBLIC, OverrideStore(), 10.0)


def _bodies(fmt: str, value) -> list[dict]:
    """One body with an unknown key on a text block/part/item, one on a tool definition."""
    if fmt == "anthropic":
        msg = {"role": "user", "content": [{"type": "text", "text": "hi", "x_note": value}]}
        tool = {"name": "t", "description": "d", "input_schema": {"type": "object"}, "x_note": value}
        return [{"messages": [msg]}, {"messages": [{"role": "user", "content": "hi"}], "tools": [tool]}]
    if fmt == "openai-responses":
        part = {"type": "input_text", "text": "hi", "x_note": value}
        item = {"type": "message", "role": "user", "content": [part]}
        tool = {"type": "function", "name": "t", "parameters": {"type": "object"}, "x_note": value}
        return [{"input": [item]}, {"input": "hi", "tools": [tool]}]
    part = {"type": "text", "text": "hi", "x_note": value}
    fn = {"name": "t", "parameters": {"type": "object"}}
    return [
        {"messages": [{"role": "user", "content": [part]}]},
        {"messages": [{"role": "user", "content": "hi"}], "tools": [{"type": "function", "function": fn, "x_note": value}]},
        {"messages": [{"role": "user", "content": "hi"}], "tools": [{"type": "function", "function": {**fn, "x_note": value}}]},
    ]


@pytest.mark.parametrize("fmt", FORMATS)
@pytest.mark.parametrize("wrap", [lambda s: s, lambda s: [s], lambda s: {"k": s}], ids=["str", "list", "dict"])
def test_unknown_nested_key_is_scanned(fmt, wrap):
    ad = ADAPTERS[fmt]
    for body in _bodies(fmt, wrap(f"see {MARKING} text")):
        d = _pipeline().evaluate(ad.extract(body))
        assert d.blocked, "the marking in an unknown key must block"
    for body in _bodies(fmt, wrap(f"connect to {HOST} now")):
        pipe = _pipeline()
        d = pipe.evaluate(ad.extract(body))
        assert not d.blocked
        assert HOST not in str(ad.apply(body, d)), "the host must be masked, never forwarded raw"
