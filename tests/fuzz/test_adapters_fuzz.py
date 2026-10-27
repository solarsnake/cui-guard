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
