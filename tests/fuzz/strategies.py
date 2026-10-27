"""Strategies and helpers for the fuzz properties. All data is synthetic."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from hypothesis import strategies as st

from cui_guard.adapters import anthropic as _an
from cui_guard.adapters import openai_chat as _chat
from cui_guard.adapters import openai_responses as _rs
from cui_guard.adapters.sse import SSEEvent, encode_event
from cui_guard.pseudo.mapper import SessionMap

FIX = Path(__file__).parents[1] / "adapters" / "fixtures"
FORMATS = ("anthropic", "openai-responses", "openai-chat")
_SEED_FILES = {
    "anthropic": "anthropic_request.json",
    "openai-responses": "openai_responses_request.json",
    "openai-chat": "openai_chat_request.json",
}
_UNTOUCHED_TOP = {
    "anthropic": _an._UNTOUCHED_KEYS,
    "openai-responses": _rs._UNTOUCHED_KEYS,
    "openai-chat": _chat._UNTOUCHED_KEYS,
}

_HANDLED_TOP = {
    "anthropic": _an._HANDLED_KEYS,
    "openai-responses": _rs._HANDLED_KEYS,
    "openai-chat": _chat._HANDLED_KEYS,
}


# -- request bodies -------------------------------------------------------

_KEY_POOL = [
    "text", "content", "input", "output", "arguments", "metadata", "label", "extra", "future_key",
    "type", "role", "name", "description", "title", "source", "data", "citations", "annotations",
    "summary", "action", "format", "tools", "messages", "system", "instructions", "id",
]  # fmt: skip
_TYPE_POOL = [
    "text", "image", "document", "tool_use", "tool_result", "thinking", "message", "reasoning",
    "function_call", "input_text", "output_text", "refusal", "custom", "function", "url", "base64",
    "unknown_future_type",
]  # fmt: skip


def seed_body(fmt: str) -> dict:
    return json.loads((FIX / _SEED_FILES[fmt]).read_text())


@st.composite
def _leaf(draw: st.DrawFn) -> Any:
    n = draw(st.integers(0, 10**6))
    return draw(
        st.one_of(
            st.text(max_size=40),
            st.just(f"CANARY-{n}-LEAF"),
            st.sampled_from(_TYPE_POOL),
            st.integers(-5, 5),
            st.booleans(),
            st.none(),
            st.floats(allow_nan=False, allow_infinity=False),
        )
    )


def _json_values(depth: int = 2) -> st.SearchStrategy:
    base = _leaf()
    if depth == 0:
        return base
    inner = _json_values(depth - 1)
    keys = st.one_of(st.sampled_from(_KEY_POOL), st.text(max_size=6))
    return st.one_of(
        base,
        st.lists(inner, max_size=3),
        st.dictionaries(keys, inner, max_size=3),
        st.fixed_dictionaries({"type": st.sampled_from(_TYPE_POOL)}, optional={"text": inner, "content": inner}),
    )


def _walk_paths(obj: Any, path: tuple = ()) -> Iterator[tuple[tuple, Any]]:
    """(path, value) for every node below the root."""
    items = obj.items() if isinstance(obj, dict) else enumerate(obj) if isinstance(obj, list) else ()
    for k, v in items:
        yield (*path, k), v
        yield from _walk_paths(v, (*path, k))


def _at(obj: Any, path: tuple) -> Any:
    for k in path:
        obj = obj[k]
    return obj


# Containers whose contents are free-form for every wire format (or are scanned whole), so a
# random key there is still valid-shaped.
_FREEFORM = frozenset({"input", "metadata", "properties", "parameters", "input_schema", "schema", "arguments"})
_STRUCTURAL = frozenset(
    {"type", "role", "id", "name", "tool_use_id", "tool_call_id", "call_id", "media_type", "status", "index", "signature", "cache_control", "is_error"}
)


_FORWARDED_TYPES = tuple({"thinking", "redacted_thinking", "reasoning", "item_reference"})


@st.composite
def request_bodies(draw: st.DrawFn, fmt: str) -> dict:
    """A fixture request mutated: string leaves swapped, values retyped, keys added or dropped.

    Keys are added at the top level and inside free-form containers; wire-format identifiers
    (type, role, id, ...) keep their type so the request stays valid-shaped.
    """
    body = seed_body(fmt)
    for _ in range(draw(st.integers(0, 4))):
        nodes = list(_walk_paths(body))
        op = draw(st.sampled_from(["leaf", "retype", "delete", "add_top", "add_free", "add_nested", "add_nested"]))
        if op == "add_top" or not nodes:
            key = draw(st.one_of(st.sampled_from(_KEY_POOL), st.text(max_size=6)))
            if key not in _HANDLED_TOP[fmt]:  # unknown top-level keys are scanned whole
                body[key] = draw(_json_values())
            continue
        if op == "add_nested":
            # An unknown key (string, list or dict value) inside a known container: a block,
            # part, item, message or tool definition. Containers whose extra keys are documented
            # as forwarded untouched (signed or reasoning items, cache hints) are left alone.
            holders = [
                p
                for p, v in nodes
                if isinstance(v, dict)
                and p[0] not in _UNTOUCHED_TOP[fmt]
                and v.get("type") not in _FORWARDED_TYPES
                and "cache_control" not in p
                and "mcp_servers" not in p
            ]
            if holders:
                holder = _at(body, draw(st.sampled_from(holders)))
                key = draw(st.one_of(st.sampled_from(_KEY_POOL), st.text(max_size=6)))
                if key not in holder and key not in _STRUCTURAL and key != "arguments":
                    holder[key] = draw(_json_values())
            continue
        if op == "add_free":
            holders = [p for p, v in nodes if isinstance(v, dict) and _FREEFORM & {k for k in p[1:] if isinstance(k, str)}]
            if holders:
                holder = _at(body, draw(st.sampled_from(holders)))
                holder[draw(st.one_of(st.sampled_from(_KEY_POOL), st.text(max_size=6)))] = draw(_json_values())
            continue
        if op == "leaf":
            cands = [p for p, v in nodes if isinstance(v, str) and p[-1] not in _STRUCTURAL]
        else:
            cands = [p for p, _ in nodes if p[-1] not in _STRUCTURAL]
        if not cands:
            continue
        path = draw(st.sampled_from(cands))
        holder = _at(body, path[:-1])
        if op == "leaf":
            holder[path[-1]] = draw(_leaf())
        elif op == "retype":
            free = _FREEFORM & {k for k in path[1:] if isinstance(k, str)} or path[0] not in _HANDLED_TOP[fmt]
            holder[path[-1]] = draw(_json_values() if free else _leaf())
        elif isinstance(holder, dict):
            del holder[path[-1]]
        else:
            del holder[path[-1]]
    return body


# -- coverage helpers -----------------------------------------------------


def string_leaves(obj: Any, fmt: str = "", path: tuple = ()) -> Iterator[tuple[tuple, str]]:
    """Every string value (never keys). JSON-text `arguments` are parsed, as the adapters do."""
    if isinstance(obj, str):
        if fmt != "anthropic" and path and path[-1] == "arguments" and obj.strip():
            try:
                inner = json.loads(obj)
            except ValueError:
                inner = None
            else:
                yield from string_leaves(inner, fmt, path)
                return
        yield path, obj
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from string_leaves(v, fmt, (*path, i))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from string_leaves(v, fmt, (*path, k))


def loc_of(path: tuple) -> str:
    """The adapters' location string for a path, e.g. messages[0].content[1]."""
    out = ""
    for k in path:
        out += f"[{k}]" if isinstance(k, int) else (f".{k}" if out else str(k))
    return out


# Wire-format discriminators and identifiers: never user text, never scanned.
_IDENTIFIERS = frozenset(
    {"type", "role", "id", "name", "tool_use_id", "tool_call_id", "call_id", "media_type", "status", "index", "signature"}
)
def untouched(fmt: str, path: tuple, opaque_locs: tuple[str, ...] = ()) -> bool:
    """True when the adapter documents this leaf as not scanned.

    Mirrors the adapter modules' skip sets (imported, not re-listed) plus the structural
    identifiers of each wire format. Opaque items are accounted for by the pipeline, so their
    contents are exempt here.
    """
    if not path:
        return False
    if path[0] in _UNTOUCHED_TOP[fmt]:
        return True
    loc = loc_of(path)
    if any(loc == o or loc.startswith((o + ".", o + "[")) for o in opaque_locs):
        return True
    keys = [k for k in path if isinstance(k, str)]
    last = path[-1]
    if path[0] not in _HANDLED_TOP[fmt]:
        return False  # unknown top-level keys are scanned whole
    if last in _IDENTIFIERS:
        return True
    if fmt == "anthropic":
        if "cache_control" in keys:
            return True  # a cache hint, forwarded as is
        if "input_schema" in keys and any(k in _an._SCHEMA_STRUCTURAL for k in keys):
            return True  # includes list entries such as required[0]
        return last in _an._CITATION_SKIP and "citations" in keys
    # OpenAI wire formats
    if "annotations" in keys and last in _rs._ANNOTATION_SKIP:
        return True
    if "format" in keys and last in _rs._FORMAT_SKIP:
        return True
    if "action" in keys and last in _rs._ACTION_SKIP:
        return True
    if last in _rs._OUTCOME_SKIP and "output" in keys:
        return True
    if ("parameters" in keys or "schema" in keys) and any(k in _an._SCHEMA_STRUCTURAL for k in keys):
        return True
    if "encrypted_content" in keys and "encrypted_content" in _rs._REASONING_KEYS:
        return True  # reasoning items are forwarded untouched
    if fmt == "openai-chat":
        if last in _chat._MESSAGE_SKIP - {"content", "tool_calls", "function_call"} and path[0] == "messages":
            return True
        if "audio" in keys and last in _chat._AUDIO_SKIP:
            return True
    return False


# -- SSE streams ----------------------------------------------------------

PLACEHOLDERS = [
    "host-01.cg.invalid", "person02@example.invalid", "CGTKT-3", "CG_PERSON_01", "CG_SECRET_01",
    "CG_TERM_01", "198.18.0.1", "CG_PERSON_77", "host-9.cg.invalid",
]  # fmt: skip


def make_map() -> SessionMap:
    m = SessionMap()
    m.placeholder_for("db.example.mil", "host")
    m.placeholder_for("Jane", "person")
    m.placeholder_for("jane@corp.example", "email")
    m.placeholder_for("TKT-1", "jira")
    m.placeholder_for("10.1.2.3", "ip")
    m.placeholder_for("s3cret-value", "secret")
    m.placeholder_for("projx", "term")
    return m


_pieces = st.lists(
    st.one_of(st.sampled_from(PLACEHOLDERS), st.sampled_from(["CG_", "host-", "198.18.", " ", "\r", "\n", "é", "日本"]), st.text(max_size=12)),
    min_size=1,
    max_size=8,
)


def _split(draw: st.DrawFn, text: str) -> list[str]:
    n = draw(st.integers(1, 6))
    cuts = sorted(draw(st.lists(st.integers(0, len(text)), min_size=n - 1, max_size=n - 1)))
    parts = [text[a:b] for a, b in zip([0, *cuts], [*cuts, len(text)], strict=True)]
    return [p for p in parts if p]


def _j(**kw: Any) -> str:
    return json.dumps(kw, ensure_ascii=False, separators=(",", ":"))


@st.composite
def _text_deltas(draw: st.DrawFn) -> list[str]:
    return _split(draw, "".join(draw(_pieces))) or [""]


@st.composite
def _tool_args(draw: st.DrawFn) -> list[str]:
    val = "".join(draw(_pieces))
    host = draw(st.sampled_from(["", "evil.example.com"]))
    return _split(draw, json.dumps({"cmd": val, "host": host}))


@st.composite
def _events(draw: st.DrawFn, fmt: str) -> list[SSEEvent]:
    evs: list[SSEEvent] = []
    for _ in range(draw(st.integers(1, 3))):
        kind = draw(st.sampled_from(["text", "tool", "junk"]))
        if kind == "junk":
            evs.append(SSEEvent("ping", _j(type="ping")))
            continue
        frags = draw(_text_deltas() if kind == "text" else _tool_args())
        i = len(evs)
        if fmt == "anthropic":
            bt = {"type": "text", "text": ""} if kind == "text" else {"type": "tool_use", "id": "t", "name": "x", "input": {}}
            dt = "text_delta" if kind == "text" else "input_json_delta"
            fk = "text" if kind == "text" else "partial_json"
            evs.append(SSEEvent("content_block_start", _j(type="content_block_start", index=i, content_block=bt)))
            for f in frags:
                evs.append(SSEEvent("content_block_delta", _j(type="content_block_delta", index=i, delta={"type": dt, fk: f})))
            evs.append(SSEEvent("content_block_stop", _j(type="content_block_stop", index=i)))
        elif fmt == "openai-responses":
            item = f"it{i}"
            if kind == "text":
                for f in frags:
                    evs.append(SSEEvent("response.output_text.delta", _j(type="response.output_text.delta", item_id=item, output_index=i, content_index=0, delta=f)))
                evs.append(SSEEvent("response.output_text.done", _j(type="response.output_text.done", item_id=item, output_index=i, content_index=0, text="".join(frags))))
            else:
                for f in frags:
                    evs.append(SSEEvent("response.function_call_arguments.delta", _j(type="response.function_call_arguments.delta", item_id=item, output_index=i, delta=f)))
                evs.append(SSEEvent("response.function_call_arguments.done", _j(type="response.function_call_arguments.done", item_id=item, output_index=i, arguments="".join(frags))))
        else:
            for f in frags:
                d = {"content": f} if kind == "text" else {"tool_calls": [{"index": 0, "function": {"arguments": f}}]}
                evs.append(SSEEvent(None, _j(id="c", object="chat.completion.chunk", choices=[{"index": 0, "delta": d, "finish_reason": None}])))
            evs.append(SSEEvent(None, _j(id="c", choices=[{"index": 0, "delta": {}, "finish_reason": "stop" if kind == "text" else "tool_calls"}])))
    if fmt == "anthropic":
        evs.append(SSEEvent("message_stop", _j(type="message_stop")))
    elif fmt == "openai-responses":
        evs.append(SSEEvent("response.completed", _j(type="response.completed", response={"output": []})))
    else:
        evs.append(SSEEvent(None, "[DONE]"))
    return evs


@st.composite
def sse_streams(draw: st.DrawFn, fmt: str) -> bytes:
    """A raw SSE byte stream for `fmt`, with random line terminators and stray comment lines."""
    eol = draw(st.sampled_from(["\n", "\r\n", "\r"]))
    out = b""
    for ev in draw(_events(fmt)):
        raw = encode_event(ev).decode()
        if draw(st.booleans()):
            raw = ": keepalive\n" + raw
        out += raw.replace("\n", eol).encode()
    return out

