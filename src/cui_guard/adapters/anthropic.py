"""Anthropic Messages adapter (/v1/messages)."""

from __future__ import annotations

import copy
import json
from typing import Any

from cui_guard.adapters.sse import SSEEvent
from cui_guard.pipeline import Decision, Opaque, RequestView, Segment
from cui_guard.pseudo.mapper import SessionMap
from cui_guard.pseudo.stream import ArgsBuffer, TextHoldback

_KNOWN_TYPES = frozenset(
    {
        "text",
        "image",
        "document",
        "tool_use",
        "tool_result",
        "thinking",
        "redacted_thinking",
        "server_tool_use",
        "web_search_tool_result",
        "search_result",
    }
)
# Signed blocks: their text is scanned read-only and never rewritten.
_PASSTHROUGH = {"thinking": "thinking", "redacted_thinking": "data"}
_TOOL_BLOCKS = frozenset({"tool_use", "server_tool_use"})
_UNTOUCHED_KEYS = frozenset({"model", "max_tokens", "stream", "temperature", "top_p", "top_k", "thinking"})
_HANDLED_KEYS = frozenset({"system", "messages", "tools", "mcp_servers"})
_SCHEMA_STRUCTURAL = frozenset({"type", "required", "$ref", "$schema", "format", "additionalProperties"})
_SCHEMA_NAME_MAPS = frozenset({"properties", "$defs", "definitions", "patternProperties"})
_CITATION_SKIP = frozenset({"type", "url", "encrypted_index", "file_id"})
_NO_KEYS: frozenset[str] = frozenset()


def _notice(kind: str) -> dict:
    return {"type": "text", "text": f"[cui-guard: {kind} removed — not scannable on this lane]"}


class _Walker:
    """Walks a request body in a fixed order; records (and optionally rewrites) it in place."""

    def __init__(self, decision: Decision | None = None) -> None:
        self.decision = decision
        self.segments: list[Segment] = []
        self.opaque: list[Opaque] = []
        self.unparseable: list[str] = []
        self.readonly: list[Segment] = []

    # -- primitives -------------------------------------------------------
    def _seg(self, loc: str, holder: Any, key: Any) -> None:
        text = holder[key]
        if not isinstance(text, str):
            self.unparseable.append(loc)
            return
        idx = len(self.segments)
        self.segments.append(Segment(idx, loc, text))
        if self.decision is not None and idx in self.decision.replacements:
            holder[key] = self.decision.replacements[idx]

    def _ro(self, loc: str, holder: Any, key: Any) -> None:
        """Record text for scanning only; it is never replaced."""
        text = holder.get(key) if isinstance(holder, dict) else None
        if not isinstance(text, str):
            self.unparseable.append(loc)
            return
        self.readonly.append(Segment(len(self.readonly), loc, text))

    def _opq(self, loc: str, kind: str) -> bool:
        """Record an opaque item; True when it must be replaced."""
        idx = len(self.opaque)
        self.opaque.append(Opaque(idx, loc, kind))
        return self.decision is not None and idx in self.decision.replace_opaque

    def _leaves(self, loc: str, holder: Any, key: Any, skip: frozenset[str] = _NO_KEYS) -> None:
        """Every string leaf (values only, never keys) becomes its own segment."""
        v = holder[key]
        if isinstance(v, str):
            self._seg(loc, holder, key)
        elif isinstance(v, list):
            for i in range(len(v)):
                self._leaves(f"{loc}[{i}]", v, i, skip)
        elif isinstance(v, dict):
            for k in list(v):
                if k not in skip:
                    self._leaves(f"{loc}.{k}", v, k, skip)

    def _opt_seg(self, loc: str, holder: dict, key: str) -> None:
        if holder.get(key) is not None:
            self._seg(loc, holder, key)

    def _schema(self, loc: str, holder: Any, key: Any, names: bool = False) -> None:
        """Schema string leaves are segments, except values under structural keywords."""
        v = holder[key]
        if isinstance(v, str):
            self._seg(loc, holder, key)
        elif isinstance(v, list):
            for i in range(len(v)):
                self._schema(f"{loc}[{i}]", v, i)
        elif isinstance(v, dict):
            for k in list(v):
                if not names and k in _SCHEMA_STRUCTURAL:
                    continue
                self._schema(f"{loc}.{k}", v, k, not names and k in _SCHEMA_NAME_MAPS)

    # -- blocks -----------------------------------------------------------
    def _content(self, loc: str, holder: Any, key: Any) -> None:
        """A content value: a string or a list of blocks."""
        c = holder[key]
        if isinstance(c, str):
            self._seg(loc, holder, key)
        elif isinstance(c, list):
            for i in range(len(c)):
                self._block(f"{loc}[{i}]", c, i)
        else:
            self.unparseable.append(loc)

    def _block(self, loc: str, holder: list, i: int) -> None:
        b = holder[i]
        t = b.get("type") if isinstance(b, dict) else None
        if t not in _KNOWN_TYPES:
            self.unparseable.append(loc)
            return
        if t in _PASSTHROUGH:
            text_key = _PASSTHROUGH[t]
            self._ro(f"{loc}.{text_key}", b, text_key)
            return
        if t == "document":
            self._document(loc, holder, i, b)
            return
        kind: str | None = None
        if t == "image":
            src = b.get("source")
            stype = src.get("type") if isinstance(src, dict) else None
            kind = "url_source" if stype in ("url", "file") else t
        elif t == "server_tool_use":
            kind = "server_tool"
        elif t == "web_search_tool_result":
            kind = "encrypted"
        if kind is not None:
            if self._opq(loc, kind):
                holder[i] = _notice(kind)
            return
        if t == "text":
            if "text" in b:
                self._seg(f"{loc}.text", b, "text")
            else:
                self.unparseable.append(loc)
            cites = b.get("citations")
            if isinstance(cites, list):
                for j in range(len(cites)):
                    self._leaves(f"{loc}.citations[{j}]", cites, j, _CITATION_SKIP)
        elif t == "tool_use":
            if isinstance(b.get("input"), dict):
                self._leaves(f"{loc}.input", b, "input")
            else:
                self.unparseable.append(loc)
        else:  # tool_result, search_result
            if t == "search_result":
                self._opt_seg(f"{loc}.title", b, "title")
                self._opt_seg(f"{loc}.source", b, "source")
            if b.get("content") is not None:
                self._content(f"{loc}.content", b, "content")

    def _document(self, loc: str, holder: list, i: int, b: dict) -> None:
        self._opt_seg(f"{loc}.title", b, "title")
        self._opt_seg(f"{loc}.context", b, "context")
        src = b.get("source")
        stype = src.get("type") if isinstance(src, dict) else None
        if stype == "text" and "data" in src:
            self._seg(f"{loc}.source.data", src, "data")
        elif stype == "content" and "content" in src:
            self._content(f"{loc}.source.content", src, "content")
        elif stype in ("url", "file", "base64"):
            kind = "document" if stype == "base64" else "url_source"
            if self._opq(loc, kind):
                holder[i] = _notice(kind)
        else:
            self.unparseable.append(loc)

    # -- body -------------------------------------------------------------
    def _tools(self, tools: Any) -> None:
        if not isinstance(tools, list):
            self.unparseable.append("tools")
            return
        keep: list[Any] = []
        for i, tool in enumerate(tools):
            loc = f"tools[{i}]"
            if not isinstance(tool, dict):
                self.unparseable.append(loc)
                keep.append(tool)
                continue
            if tool.get("type") not in (None, "custom"):
                if self._opq(loc, "server_tool"):
                    continue
                keep.append(tool)
                continue
            if "description" in tool:
                self._seg(f"{loc}.description", tool, "description")
            if "input_schema" in tool:
                self._schema(f"{loc}.input_schema", tool, "input_schema")
            keep.append(tool)
        if self.decision is not None:
            tools[:] = keep

    def walk(self, body: dict) -> None:
        if "system" in body:
            self._content("system", body, "system")
        msgs = body.get("messages")
        if not isinstance(msgs, list):
            self.unparseable.append("messages")
        else:
            for i, m in enumerate(msgs):
                if isinstance(m, dict) and "content" in m:
                    self._content(f"messages[{i}].content", m, "content")
                else:
                    self.unparseable.append(f"messages[{i}]")
        if "tools" in body:
            self._tools(body["tools"])
        for k in list(body):
            if k in _HANDLED_KEYS or k in _UNTOUCHED_KEYS:
                continue
            self._leaves(k, body, k)
        if "mcp_servers" in body and self._opq("mcp_servers", "server_tool"):
            del body["mcp_servers"]


def _rehydrate_tree(obj: Any, smap: SessionMap) -> Any:
    if isinstance(obj, str):
        return smap.rehydrate(obj)
    if isinstance(obj, list):
        return [_rehydrate_tree(v, smap) for v in obj]
    if isinstance(obj, dict):
        # Keys are never scanned outbound, so they are never rehydrated.
        return {k: _rehydrate_tree(v, smap) for k, v in obj.items()}
    return obj


def _rehydrate_blocks(blocks: Any, smap: SessionMap) -> None:
    if not isinstance(blocks, list):
        return
    for b in blocks:
        if not isinstance(b, dict):
            continue
        if b.get("type") == "text" and isinstance(b.get("text"), str):
            b["text"] = smap.rehydrate(b["text"])
            for c in b.get("citations") or []:
                if isinstance(c, dict):
                    for k in ("cited_text", "document_title"):
                        if isinstance(c.get(k), str):
                            c[k] = smap.rehydrate(c[k])
        elif b.get("type") in _TOOL_BLOCKS and "input" in b:
            b["input"] = _rehydrate_tree(b["input"], smap)


def _dump(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


class _AnthropicStream:
    def __init__(self, smap: SessionMap) -> None:
        self._smap = smap
        self._text: dict[int, TextHoldback] = {}
        self._args: dict[int, ArgsBuffer] = {}
        self._has_args: set[int] = set()
        self._leftover = 0
        self.notes: list[str] = []

    def _count(self, text: str) -> None:
        n = len(self._smap.leftover_placeholders(text))
        if n:
            self._leftover += n
            self.notes[:] = [f"leftover_placeholders={self._leftover}"]

    @property
    def pending(self) -> bool:
        """True while text is held back or tool-call arguments are buffered."""
        return bool(self._has_args) or any(hb._pending for hb in self._text.values())

    @staticmethod
    def _delta_event(index: int, delta: dict) -> SSEEvent:
        return SSEEvent(
            "content_block_delta",
            _dump({"type": "content_block_delta", "index": index, "delta": delta}),
        )

    def _text_delta(self, index: int, text: str) -> list[SSEEvent]:
        if not text:
            return []
        self._count(text)
        return [self._delta_event(index, {"type": "text_delta", "text": text})]

    def feed(self, ev: SSEEvent) -> list[SSEEvent]:
        try:
            data = json.loads(ev.data)
        except ValueError as e:
            raise ValueError("unparseable SSE data") from e
        if not isinstance(data, dict):
            raise TypeError("unexpected SSE data shape")
        t = data.get("type")
        if t == "message_start":
            msg = data.get("message")
            if isinstance(msg, dict) and msg.get("content"):
                _rehydrate_blocks(msg["content"], self._smap)
                return [SSEEvent(ev.event, _dump(data))]
            return [ev]
        if t == "content_block_start":
            return self._start(ev, data)
        if t == "content_block_delta":
            return self._delta(ev, data)
        if t == "content_block_stop":
            return self._stop(ev, data)
        return [ev]

    def _start(self, ev: SSEEvent, data: dict) -> list[SSEEvent]:
        idx = data.get("index")
        block = data.get("content_block")
        btype = block.get("type") if isinstance(block, dict) else None
        if btype == "text":
            self._text[idx] = TextHoldback(self._smap)
            if block.get("text"):
                block["text"] = self._smap.rehydrate(block["text"])
                return [SSEEvent(ev.event, _dump(data))]
        elif btype in _TOOL_BLOCKS:
            self._args[idx] = ArgsBuffer()
        return [ev]

    def _delta(self, ev: SSEEvent, data: dict) -> list[SSEEvent]:
        idx = data.get("index")
        delta = data.get("delta")
        dtype = delta.get("type") if isinstance(delta, dict) else None
        if dtype == "text_delta":
            hb = self._text.setdefault(idx, TextHoldback(self._smap))
            out = hb.feed(delta.get("text", ""))
            if not out:
                return []
            self._count(out)
            delta["text"] = out
            return [SSEEvent(ev.event, _dump(data))]
        if dtype == "input_json_delta":
            frag = delta.get("partial_json", "")
            self._args.setdefault(idx, ArgsBuffer()).feed(frag)
            if frag.strip():
                self._has_args.add(idx)
            return []
        if dtype == "citations_delta" and isinstance(delta.get("citation"), dict):
            new = _rehydrate_tree(delta["citation"], self._smap)
            if new != delta["citation"]:
                delta["citation"] = new
                return [SSEEvent(ev.event, _dump(data))]
        return [ev]

    def _stop(self, ev: SSEEvent, data: dict) -> list[SSEEvent]:
        idx = data.get("index")
        out: list[SSEEvent] = []
        hb = self._text.pop(idx, None)
        if hb is not None:
            out += self._text_delta(idx, hb.flush())
        buf = self._args.pop(idx, None)
        if buf is not None and idx in self._has_args:
            self._has_args.discard(idx)
            full = buf.finish(self._smap)
            self._count(full)
            out.append(self._delta_event(idx, {"type": "input_json_delta", "partial_json": full}))
        out.append(ev)
        return out

    def finish(self) -> list[SSEEvent]:
        out: list[SSEEvent] = []
        for idx, hb in list(self._text.items()):
            out += self._text_delta(idx, hb.flush())
        self._text.clear()
        if self._args:
            self.notes.append(f"incomplete_tool_blocks={len(self._args)}")
        self._args.clear()  # incomplete tool JSON is never forwarded
        self._has_args.clear()
        return out


class AnthropicAdapter:
    format = "anthropic"
    paths = ("/v1/messages",)
    block_status = 400

    def extract(self, body: dict) -> RequestView:
        w = _Walker()
        w.walk(body)
        return RequestView(w.segments, w.opaque, w.unparseable, w.readonly)

    def apply(self, body: dict, decision: Decision) -> dict:
        new = copy.deepcopy(body)
        _Walker(decision).walk(new)
        return new

    def rehydrate_response(self, body: dict, smap: SessionMap) -> dict:
        new = copy.deepcopy(body)
        _rehydrate_blocks(new.get("content"), smap)
        return new

    def stream_rewriter(self, smap: SessionMap) -> _AnthropicStream:
        return _AnthropicStream(smap)

    def keepalive(self) -> SSEEvent:
        return SSEEvent("ping", _dump({"type": "ping"}))

    def error_body(self, message: str) -> dict:
        return {"type": "error", "error": {"type": "invalid_request_error", "message": message}}
