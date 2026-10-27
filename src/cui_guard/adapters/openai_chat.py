"""OpenAI Chat Completions adapter (/v1/chat/completions)."""

from __future__ import annotations

import copy
import json
from typing import Any

from cui_guard.adapters.openai_responses import (
    OpenAIWalker,
    dump,
    finish_args,
    notice,
    rehydrate_tree,
)
from cui_guard.adapters.sse import SSEEvent
from cui_guard.pipeline import Decision, RequestView
from cui_guard.pseudo.mapper import SessionMap
from cui_guard.pseudo.stream import ArgsBuffer, TextHoldback, rehydrate_call_fields

_UNTOUCHED_KEYS = frozenset(
    {
        "model", "stream", "temperature", "top_p", "max_tokens", "max_output_tokens",
        "max_completion_tokens", "n", "seed", "store", "parallel_tool_calls", "reasoning",
        "service_tier", "stream_options", "truncation", "include", "previous_response_id",
        "user", "prompt_cache_key", "safety_identifier",
    }
)  # fmt: skip
_HANDLED_KEYS = frozenset({"messages", "tools", "functions"})
_MESSAGE_SKIP = frozenset(
    {"role", "tool_call_id", "id", "audio", "content", "tool_calls", "function_call"}
)
_AUDIO_SKIP = frozenset({"id"})
# Keys each container handles itself or that only identify it; any other key has its string
# leaves scanned (see _Walker._extra).
_CPART_TEXT_KEYS = frozenset({"type", "text"})
_CPART_REFUSAL_KEYS = frozenset({"type", "refusal"})
_TOOL_CALL_KEYS = frozenset({"id", "index", "type", "function", "custom"})
_FN_CALL_KEYS = frozenset({"name", "arguments"})
_CUSTOM_CALL_KEYS = frozenset({"name", "input"})
_TOOL_ENTRY_KEYS = frozenset({"type", "function", "custom"})
_FN_DEF_KEYS = frozenset({"name", "description", "parameters"})
_TEMPLATE_KEYS = ("id", "object", "created", "model", "system_fingerprint", "service_tier")


class _ChatWalker(OpenAIWalker):
    def _cparts(self, loc: str, holder: Any, key: Any) -> None:
        c = holder[key]
        if isinstance(c, str):
            self._seg(loc, holder, key)
        elif isinstance(c, list):
            for i in range(len(c)):
                self._cpart(f"{loc}[{i}]", c, i)
        else:
            self.unparseable.append(loc)

    def _cpart(self, loc: str, parts: list, i: int) -> None:
        p = parts[i]
        t = p.get("type") if isinstance(p, dict) else None
        kind: str | None = None
        if t == "text" and "text" in p:
            self._seg(f"{loc}.text", p, "text")
            self._extra(loc, p, _CPART_TEXT_KEYS)
        elif t == "refusal" and "refusal" in p:
            self._seg(f"{loc}.refusal", p, "refusal")
            self._extra(loc, p, _CPART_REFUSAL_KEYS)
        elif t == "image_url":
            kind = "image"
        elif t == "input_audio":
            kind = "document"
        elif t == "file":
            f = p.get("file")
            kind = "url_source" if isinstance(f, dict) and f.get("file_id") else "document"
        else:
            self.unparseable.append(loc)
        if kind is not None and self._opq(loc, kind):
            parts[i] = {"type": "text", "text": notice(kind)}

    def _message(self, loc: str, m: Any) -> None:
        if not isinstance(m, dict):
            self.unparseable.append(loc)
            return
        if m.get("content") is not None:
            self._cparts(f"{loc}.content", m, "content")
        calls = m.get("tool_calls")
        if calls is not None:
            if not isinstance(calls, list):
                self.unparseable.append(f"{loc}.tool_calls")
                calls = []
            for j, tc in enumerate(calls):
                cl = f"{loc}.tool_calls[{j}]"
                t = tc.get("type") if isinstance(tc, dict) else None
                fn = tc.get(t) if t in ("function", "custom") else None
                if not isinstance(fn, dict):
                    self.unparseable.append(cl)
                elif t == "function" and "arguments" in fn:
                    self.args(f"{cl}.function.arguments", fn, "arguments")
                elif t == "custom" and "input" in fn:
                    self._seg(f"{cl}.custom.input", fn, "input")
                else:
                    self.unparseable.append(cl)
                if isinstance(tc, dict):
                    self._extra(cl, tc, _TOOL_CALL_KEYS)
                    if isinstance(fn, dict):
                        self._extra(f"{cl}.{t}", fn, _FN_CALL_KEYS if t == "function" else _CUSTOM_CALL_KEYS)
        legacy = m.get("function_call")
        if legacy is not None:
            if isinstance(legacy, dict) and "arguments" in legacy:
                self.args(f"{loc}.function_call.arguments", legacy, "arguments")
                self._extra(f"{loc}.function_call", legacy, _FN_CALL_KEYS)
            else:
                self.unparseable.append(f"{loc}.function_call")
        if "audio" in m:
            self._leaves(f"{loc}.audio", m, "audio", _AUDIO_SKIP)
        for k in list(m):
            if k not in _MESSAGE_SKIP:
                self._leaves(f"{loc}.{k}", m, k)

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
            t = tool.get("type")
            if t in (None, "function"):
                fn = tool.get("function")
                if isinstance(fn, dict):
                    self._function_def(f"{loc}.function", fn)
                else:
                    self.unparseable.append(loc)
            elif t == "custom" and isinstance(tool.get("custom"), dict):
                self.custom_tool(f"{loc}.custom", tool["custom"])
            elif t != "custom" and self._opq(loc, "server_tool"):
                continue
            elif t == "custom":
                self.unparseable.append(loc)
            self._extra(loc, tool, _TOOL_ENTRY_KEYS)
            keep.append(tool)
        if self.decision is not None:
            tools[:] = keep

    def _function_def(self, loc: str, fn: dict) -> None:
        if "description" in fn:
            self._seg(f"{loc}.description", fn, "description")
        if "parameters" in fn:
            self._schema(f"{loc}.parameters", fn, "parameters")
        self._extra(loc, fn, _FN_DEF_KEYS)

    def walk(self, body: dict) -> None:
        msgs = body.get("messages")
        if not isinstance(msgs, list):
            self.unparseable.append("messages")
        else:
            for i, m in enumerate(msgs):
                self._message(f"messages[{i}]", m)
        if "tools" in body:
            self._tools(body["tools"])
        if "functions" in body:
            fns = body["functions"]
            if isinstance(fns, list) and all(isinstance(f, dict) for f in fns):
                for i, f in enumerate(fns):
                    self._function_def(f"functions[{i}]", f)
            else:
                self.unparseable.append("functions")
        for k in list(body):
            if k in _HANDLED_KEYS or k in _UNTOUCHED_KEYS:
                continue
            self._leaves(k, body, k)


_FC = -1  # tool index used for the legacy delta.function_call
_CALL_IDS = frozenset({"id", "index", "type"})


def _rehydrate_call(tc: Any, smap: SessionMap) -> Any:
    """One `tool_calls` entry, decided as one call. `function`/`custom` keep their `name`;
    any other shape is taken whole as a call (fail closed)."""
    if not isinstance(tc, dict):
        return rehydrate_tree(tc, smap)
    t = tc.get("type")
    body = tc.get(t) if isinstance(t, str) else None
    if isinstance(body, dict):
        rest = {k: v for k, v in body.items() if k != "name"}
        return {**tc, t: {**body, **rehydrate_call_fields(rest, smap)}}
    rest = {k: v for k, v in tc.items() if k not in _CALL_IDS}
    return {**tc, **rehydrate_call_fields(rest, smap)}


def rehydrate_message(msg: Any, smap: SessionMap) -> Any:
    """Content and refusals are text; each tool call is egress-checked as one call."""
    if not isinstance(msg, dict):
        return rehydrate_tree(msg, smap)
    out = {}
    for k, v in msg.items():
        if k == "tool_calls" and isinstance(v, list):
            out[k] = [_rehydrate_call(tc, smap) for tc in v]
        elif k == "function_call" and isinstance(v, dict):
            rest = {kk: vv for kk, vv in v.items() if kk != "name"}
            out[k] = {**v, **rehydrate_call_fields(rest, smap)}
        else:
            out[k] = rehydrate_tree(v, smap, k)
    return out


class _ChatStream:
    def __init__(self, smap: SessionMap) -> None:
        self._smap = smap
        self._text: dict[int, TextHoldback] = {}
        self._refusal: dict[int, TextHoldback] = {}
        self._calls: dict[tuple[int, int], ArgsBuffer] = {}
        self._has_args: set[tuple[int, int]] = set()
        self._custom: dict[tuple[int, int], list[str]] = {}  # custom tool input fragments
        self._tmpl: dict[str, Any] = {}
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
        return (
            bool(self._has_args)
            or any(any(p) for p in self._custom.values())
            or any(hb._pending for hb in self._text.values())
            or any(hb._pending for hb in self._refusal.values())
        )

    def _chunk(self, choice: dict) -> SSEEvent:
        return SSEEvent(None, dump({**self._tmpl, "choices": [choice]}))

    def feed(self, ev: SSEEvent) -> list[SSEEvent]:
        if ev.data.strip() == "[DONE]":
            return [ev]
        try:
            data = json.loads(ev.data)
        except ValueError as e:
            raise ValueError("unparseable SSE data") from e
        if not isinstance(data, dict):
            raise TypeError("unexpected SSE data shape")
        choices = data.get("choices")
        if not isinstance(choices, list):
            return [ev]
        for k in _TEMPLATE_KEYS:
            if k in data:
                self._tmpl[k] = data[k]
        pre: list[SSEEvent] = []
        droppable: list[bool] = []
        for ch in choices:
            if not isinstance(ch, dict):
                droppable.append(False)
                continue
            ci = ch.get("index", 0)
            fin = ch.get("finish_reason")
            delta = ch.get("delta")
            drop = False
            if isinstance(delta, dict):
                drop = self._delta(ci, delta, fin)
            if fin is not None:
                pre += self._emit_calls(ci)
                for store, key in ((self._text, "content"), (self._refusal, "refusal")):
                    hb = store.pop(ci, None)
                    tail = hb.flush() if hb is not None else ""
                    if tail:
                        self._count(tail)
                        d = ch.setdefault("delta", {})
                        if isinstance(d, dict):
                            d[key] = (d.get(key) or "") + tail
            droppable.append(drop)
        if choices and all(droppable):
            return pre
        return [*pre, SSEEvent(ev.event, dump(data))]

    def _delta(self, ci: int, delta: dict, fin: Any) -> bool:
        """Rewrite a delta in place; True when the chunk carries nothing left to forward."""
        touched = False
        emptied: set[str] = set()
        for key, store in (("content", self._text), ("refusal", self._refusal)):
            val = delta.get(key)
            if isinstance(val, str):
                out = store.setdefault(ci, TextHoldback(self._smap)).feed(val)
                if out:
                    self._count(out)
                delta[key] = out
                if val and not out:
                    touched = True
                    emptied.add(key)
        fc = delta.get("function_call")
        if isinstance(fc, dict) and "arguments" in fc:
            self._buffer((ci, _FC), fc["arguments"])
            fc["arguments"] = ""
            if set(fc) <= {"arguments"}:
                del delta["function_call"]  # re-emitted whole before the finish chunk
                touched = True
        calls = delta.get("tool_calls")
        if isinstance(calls, list):
            kept = []
            for tc in calls:
                if not isinstance(tc, dict):
                    kept.append(tc)
                    continue
                fn = tc.get("function")
                if isinstance(fn, dict) and "arguments" in fn:
                    self._buffer((ci, tc.get("index", 0)), fn["arguments"])
                    fn["arguments"] = ""
                    if set(tc) <= {"index", "function"} and set(fn) <= {"arguments"}:
                        continue  # a bare argument fragment, re-emitted whole later
                cu = tc.get("custom")
                if isinstance(cu, dict) and "input" in cu:
                    frag = cu["input"]
                    key = (ci, tc.get("index", 0))
                    self._custom.setdefault(key, []).append(frag if isinstance(frag, str) else "")
                    cu["input"] = ""
                    if set(tc) <= {"index", "custom"} and set(cu) <= {"input"}:
                        continue  # a bare input fragment, re-emitted whole later
                kept.append(tc)
            if kept:
                delta["tool_calls"] = kept
            else:
                del delta["tool_calls"]
                touched = True
        return touched and fin is None and set(delta) <= emptied

    def _buffer(self, key: tuple[int, int], frag: Any) -> None:
        text = frag if isinstance(frag, str) else ""
        self._calls.setdefault(key, ArgsBuffer()).feed(text)
        if text.strip():
            self._has_args.add(key)

    def _emit_calls(self, ci: int) -> list[SSEEvent]:
        delta: dict[str, Any] = {}
        for key in sorted(k for k in self._custom if k[0] == ci):
            text = "".join(self._custom.pop(key))
            if not text:
                continue
            full = self._smap.rehydrate_tool(text)  # the whole input is the call
            self._count(full)
            delta.setdefault("tool_calls", []).append({"index": key[1], "custom": {"input": full}})
        for key in sorted(k for k in self._calls if k[0] == ci):
            buf = self._calls.pop(key)
            if key not in self._has_args:
                continue
            self._has_args.discard(key)
            full = finish_args(buf, self._smap)
            self._count(full)
            if key[1] == _FC:
                delta["function_call"] = {"arguments": full}
            else:
                delta.setdefault("tool_calls", []).append(
                    {"index": key[1], "function": {"arguments": full}}
                )
        if not delta:
            return []
        return [self._chunk({"index": ci, "delta": delta, "finish_reason": None})]

    def finish(self) -> list[SSEEvent]:
        out: list[SSEEvent] = []
        for store, key in ((self._text, "content"), (self._refusal, "refusal")):
            for ci, hb in list(store.items()):
                tail = hb.flush()
                if tail:
                    self._count(tail)
                    out.append(self._chunk({"index": ci, "delta": {key: tail}, "finish_reason": None}))
            store.clear()
        if self._calls or self._custom:
            self.notes.append(f"incomplete_tool_blocks={len(self._calls) + len(self._custom)}")
        self._calls.clear()  # incomplete tool JSON is never forwarded
        self._has_args.clear()
        self._custom.clear()
        return out


class OpenAIChatAdapter:
    format = "openai-chat"
    paths = ("/v1/chat/completions",)
    block_status = 400

    def extract(self, body: dict) -> RequestView:
        w = _ChatWalker()
        w.walk(body)
        return RequestView(w.segments, w.opaque, w.unparseable)

    def apply(self, body: dict, decision: Decision) -> dict:
        new = copy.deepcopy(body)
        _ChatWalker(decision).walk(new)
        return new

    def rehydrate_response(self, body: dict, smap: SessionMap) -> dict:
        new = copy.deepcopy(body)
        choices = new.get("choices")
        if isinstance(choices, list):
            for ch in choices:
                if isinstance(ch, dict) and "message" in ch:
                    ch["message"] = rehydrate_message(ch["message"], smap)
        return new

    def stream_rewriter(self, smap: SessionMap) -> _ChatStream:
        return _ChatStream(smap)

    def keepalive(self) -> bytes:
        return b": keepalive\n\n"

    def error_body(self, message: str) -> dict:
        return {
            "error": {
                "message": message,
                "type": "invalid_request_error",
                "code": "cui_guard_blocked",
            }
        }
