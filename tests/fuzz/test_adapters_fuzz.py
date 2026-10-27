"""Coverage invariant: no request string leaf is forwarded unscanned."""

from __future__ import annotations

import copy
import re

import pytest
from hypothesis import given

from cui_guard.adapters.anthropic import AnthropicAdapter
from cui_guard.adapters.openai_chat import OpenAIChatAdapter
from cui_guard.adapters.openai_responses import OpenAIResponsesAdapter
from cui_guard.detect.engine import Detector
from cui_guard.detect.identifiers import IdentifierConfig
from cui_guard.detect.rules import load_builtin_rules
from cui_guard.model import Trust
from cui_guard.override.store import OverrideStore
from cui_guard.pipeline import Pipeline
from cui_guard.policy.loader import load_builtin_layer
from cui_guard.policy.merge import merge_layers

from .strategies import (
    FORMATS,
    REAL_VALUES,
    loc_of,
    make_map,
    request_bodies,
    string_leaves,
    untouched,
)

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
        # Compare locations, not texts: a leaf must be scanned where it sits.
        scanned = {s.location: s.text for s in [*view.segments, *view.readonly]}
        opaque = tuple(o.location for o in view.opaque)
        for path, leaf in string_leaves(body, fmt):
            if leaf == "":
                continue  # nothing to scan
            if untouched(fmt, path, opaque):
                continue
            assert scanned.get(loc_of(path)) == leaf, path

    prop()


_DETECTOR = Detector(
    load_builtin_rules(),
    IdentifierConfig(
        domains=("example.mil",),
        ip_ranges=("10.0.0.0/8",),
        codenames=("projx",),
        jira_projects=("TKT",),
        people=("Jane",),
    ),
)
_POLICY = merge_layers(load_builtin_layer(), None, None)


@pytest.mark.parametrize("fmt", FORMATS)
def test_applied_body_holds_no_real_value(fmt):
    """extract -> evaluate (public lane) -> apply: a real value never survives in a leaf the
    adapter does not document as untouched, whatever the opaque items and unknown keys."""

    @given(body=request_bodies(fmt))
    def prop(body):
        ad = ADAPTERS[fmt]
        view = ad.extract(copy.deepcopy(body))
        if view.unparseable:
            return
        d = Pipeline(_POLICY, _DETECTOR, make_map(), Trust.PUBLIC, OverrideStore(), 10.0).evaluate(view)
        if d.blocked:
            return  # nothing is forwarded
        applied = ad.apply(copy.deepcopy(body), d)
        opaque = tuple(o.location for o in ad.extract(copy.deepcopy(applied)).opaque)
        for path, leaf in string_leaves(applied, fmt):
            if not untouched(fmt, path, opaque):
                for real in REAL_VALUES:
                    assert not re.search(rf"(?<![A-Za-z0-9]){re.escape(real)}", leaf), (path, real)

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
    return Pipeline(_POLICY, Detector(load_builtin_rules(), IdentifierConfig()), make_map(), Trust.PUBLIC, OverrideStore(), 10.0)


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


# -- fix round 1 regressions ---------------------------------------------


def test_server_tool_extra_key_keeps_segment_indices_aligned():
    # The sweep once ran for a server tool when recording but not when applying (the opaque
    # item is dropped), so every later segment was rewritten at the wrong index.
    ad = ADAPTERS["openai-chat"]
    body = {
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{"type": "web_search", "note": "plain words"}],
        "x_extra": f"connect to {HOST} now",
    }
    pipe = _pipeline()
    d = pipe.evaluate(ad.extract(body))
    assert d.replace_opaque
    assert HOST not in str(ad.apply(body, d))


def test_sibling_of_declared_tool_type_is_scanned():
    chat = ADAPTERS["openai-chat"]
    entry = {"type": "function", "function": {"name": "t"}, "custom": {"description": "CANARYX"}}
    call = {"id": "c", "type": "function", "function": {"name": "t", "arguments": ""}, "custom": {"input": "CANARYX"}}
    v = chat.extract({"messages": [{"role": "user", "content": "hi"}], "tools": [entry]})
    assert "CANARYX" in {s.text for s in v.segments}
    v = chat.extract({"messages": [{"role": "assistant", "content": "hi", "tool_calls": [call]}]})
    assert "CANARYX" in {s.text for s in v.segments}


def test_never_modified_items_scan_unknown_keys_read_only():
    an = ADAPTERS["anthropic"]
    for block in (
        {"type": "thinking", "thinking": "t", "signature": "s", "note": f"see {MARKING}"},
        {"type": "redacted_thinking", "data": "d", "note": f"see {MARKING}"},
    ):
        v = an.extract({"messages": [{"role": "assistant", "content": [block]}]})
        assert any(MARKING in s.text for s in v.readonly), block["type"]
        assert _pipeline().evaluate(v).blocked
    rs = ADAPTERS["openai-responses"]
    v = rs.extract({"input": [{"type": "item_reference", "id": "i", "note": {"k": [f"see {MARKING}"]}}]})
    assert any(MARKING in s.text for s in v.readonly)
    assert _pipeline().evaluate(v).blocked
    # and they are never rewritten
    body = {"messages": [{"role": "assistant", "content": [{"type": "thinking", "thinking": "t", "signature": "s", "note": HOST}]}]}
    assert an.apply(body, _pipeline().evaluate(an.extract(body))) == body


def test_identifier_keys_holding_containers_are_unparseable():
    an, rs, chat = ADAPTERS["anthropic"], ADAPTERS["openai-responses"], ADAPTERS["openai-chat"]
    text = {"type": "text", "text": "t"}
    cases = [
        (an, {"messages": [{"role": ["CANARYX"], "content": "t"}]}),
        (an, {"messages": [{"role": "assistant", "content": [{"type": "tool_use", "id": {"a": "CANARYX"}, "name": "n", "input": {}}]}]}),
        (an, {"messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "i", "content": "t", "is_error": "CANARYX"}]}]}),
        (an, {"messages": [{"role": "user", "content": [{**text, "cache_control": "CANARYX"}]}]}),
        (chat, {"messages": [{"role": {"a": "CANARYX"}, "content": "t"}]}),
        (rs, {"input": [{"type": "message", "role": ["CANARYX"], "content": "t"}]}),
    ]
    for ad, body in cases:
        assert ad.extract(body).unparseable, body


def test_schema_under_structural_keyword_is_scanned():
    an = ADAPTERS["anthropic"]
    schema = {"type": "object", "additionalProperties": {"type": "string", "description": f"see {MARKING}"}}
    v = an.extract({"messages": [{"role": "user", "content": "t"}], "tools": [{"name": "n", "input_schema": schema}]})
    assert any(MARKING in s.text for s in v.segments)
