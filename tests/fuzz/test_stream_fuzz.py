"""Rehydration must not depend on how the byte stream is chunked."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cui_guard.adapters.anthropic import AnthropicAdapter
from cui_guard.adapters.openai_chat import OpenAIChatAdapter
from cui_guard.adapters.openai_responses import OpenAIResponsesAdapter
from cui_guard.adapters.sse import SSEDecoder, encode_event

from .strategies import FORMATS, make_map, sse_streams

ADAPTERS = {
    "anthropic": AnthropicAdapter(),
    "openai-responses": OpenAIResponsesAdapter(),
    "openai-chat": OpenAIChatAdapter(),
}


def run(fmt: str, chunks: list[bytes]) -> tuple[bytes, list[str]]:
    """Feed chunks through the decoder and rewriter exactly as the gateway does."""
    rw = ADAPTERS[fmt].stream_rewriter(make_map())
    dec = SSEDecoder()
    out = b""
    try:
        for chunk in chunks:
            for ev in dec.feed(chunk):
                for o in rw.feed(ev):
                    out += encode_event(o)
        for ev in dec.close():
            for o in rw.feed(ev):
                out += encode_event(o)
        for o in rw.finish():
            out += encode_event(o)
    except (ValueError, TypeError) as e:  # the gateway's fail-closed path
        out += b"!" + type(e).__name__.encode()
    return out, rw.notes


def split(raw: bytes, cuts: list[int]) -> list[bytes]:
    chunks, pos = [], 0
    for c in cuts:
        if pos >= len(raw):
            break
        chunks.append(raw[pos : pos + c])
        pos += c
    chunks.append(raw[pos:])
    return chunks


@pytest.mark.parametrize("fmt", FORMATS)
def test_rehydration_independent_of_chunking(fmt):
    @given(raw=sse_streams(fmt), cuts=st.lists(st.integers(1, 64)))
    def prop(raw, cuts):
        assert run(fmt, split(raw, cuts)) == run(fmt, [raw])

    prop()
