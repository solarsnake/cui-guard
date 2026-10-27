"""OpenAI Responses adapter (/v1/responses)."""

from __future__ import annotations

import copy
import json
from typing import Any

from cui_guard.adapters.anthropic import _Walker
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
_HANDLED_KEYS = frozenset({"instructions", "input", "tools"})
_SERVER_ITEMS = frozenset(
    {
        "web_search_call", "file_search_call", "code_interpreter_call", "computer_call",
        "computer_call_output", "image_generation_call", "mcp_call", "mcp_list_tools",
        "mcp_approval_request", "mcp_approval_response",
    }
)  # fmt: skip
_PASSTHROUGH_ITEMS = frozenset({"item_reference"})
_ANNOTATION_SKIP = frozenset(
    {"type", "url", "file_id", "container_id", "index", "start_index", "end_index"}
)
_FORMAT_SKIP = frozenset({"type", "syntax"})
_ACTION_SKIP = frozenset({"type"})
_OUTCOME_SKIP = frozenset({"outcome"})
# Keys each container handles itself or that only identify it; any other key has its string
# leaves scanned (see _Walker._extra).
_PART_TEXT_KEYS = frozenset({"type", "text", "annotations"})
_PART_REFUSAL_KEYS = frozenset({"type", "refusal"})
_ITEM_KEYS = {
    "message": frozenset({"type", "id", "status", "role", "content"}),
    "function_call": frozenset({"type", "id", "status", "call_id", "name", "arguments"}),
    "function_call_output": frozenset({"type", "id", "status", "call_id", "output"}),
    "custom_tool_call_output": frozenset({"type", "id", "status", "call_id", "output"}),
    "local_shell_call_output": frozenset({"type", "id", "status", "call_id", "output"}),
    "custom_tool_call": frozenset({"type", "id", "status", "call_id", "name", "input"}),
    "local_shell_call": frozenset({"type", "id", "status", "call_id", "action"}),
    "shell_call": frozenset({"type", "id", "status", "call_id", "action"}),
    "shell_call_output": frozenset({"type", "id", "status", "call_id", "output"}),
}
_FUNCTION_TOOL_KEYS = frozenset({"type", "name", "description", "parameters"})
_CUSTOM_TOOL_KEYS = frozenset({"type", "name", "description", "format"})
# Anything else on a reasoning item could carry unscanned text.
_REASONING_PART_KEYS = frozenset({"type", "text"})
_REASONING_KEYS = frozenset({"type", "id", "summary", "content", "encrypted_content", "status"})


def notice(kind: str) -> str:
    return f"[cui-guard: {kind} removed — not scannable on this lane]"


def dump(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


class OpenAIWalker(_Walker):
    """Shared primitives for the two OpenAI wire formats."""

    def args(self, loc: str, holder: Any, key: Any) -> None:
        """A JSON-string arguments value: each string leaf is a segment."""
        raw = holder[key]
        if not isinstance(raw, str):
            self.unparseable.append(loc)
            return
        if not raw.strip():
            return
        try:
            obj = json.loads(raw)
        except ValueError:
            self.unparseable.append(loc)
            return
        before = copy.deepcopy(obj)
        box = {"v": obj}
        self._leaves(loc, box, "v")
        if self.decision is not None and box["v"] != before:
            holder[key] = dump(box["v"])

    def custom_tool(self, loc: str, tool: dict) -> None:
        if "description" in tool:
            self._seg(f"{loc}.description", tool, "description")
        if "format" in tool:
            self._leaves(f"{loc}.format", tool, "format", _FORMAT_SKIP)
        self._extra(loc, tool, _CUSTOM_TOOL_KEYS)

    # -- Responses input --------------------------------------------------
    def _parts(self, loc: str, holder: Any, key: Any) -> None:
        c = holder[key]
        if isinstance(c, str):
            self._seg(loc, holder, key)
        elif isinstance(c, list):
            for i in range(len(c)):
                self._part(f"{loc}[{i}]", c, i)
        else:
            self.unparseable.append(loc)

    def _part(self, loc: str, parts: list, i: int) -> None:
        p = parts[i]
        t = p.get("type") if isinstance(p, dict) else None
        kind: str | None = None
        if t in ("input_text", "output_text"):
            if "text" in p:
                self._seg(f"{loc}.text", p, "text")
            else:
                self.unparseable.append(loc)
            anns = p.get("annotations")
            if isinstance(anns, list):
                for j in range(len(anns)):
                    self._leaves(f"{loc}.annotations[{j}]", anns, j, _ANNOTATION_SKIP)
            elif anns is not None:
                self.unparseable.append(f"{loc}.annotations")  # never forward an unscanned value
            self._extra(loc, p, _PART_TEXT_KEYS)
        elif t == "refusal":
            if "refusal" in p:
                self._seg(f"{loc}.refusal", p, "refusal")
            else:
                self.unparseable.append(loc)
            self._extra(loc, p, _PART_REFUSAL_KEYS)
        elif t == "input_image":
            kind = "image"
        elif t == "input_file":
            kind = "url_source" if (p.get("file_url") or p.get("file_id")) else "document"
        else:
            self.unparseable.append(loc)
        if kind is not None and self._opq(loc, kind):
            parts[i] = {"type": "input_text", "text": notice(kind)}

    def _item(self, loc: str, items: list, i: int) -> None:
        it = items[i]
        t = it.get("type") if isinstance(it, dict) else None
        if isinstance(it, dict) and t is None and "role" in it:
            t = "message"
        if not isinstance(t, str):
            self.unparseable.append(loc)  # a non-string type is unhashable and unknown
            return
        if t in _PASSTHROUGH_ITEMS:
            for k, v in it.items():  # never modified: everything but type and id is read-only text
                if k != "type" and not (k == "id" and isinstance(v, str)):
                    self._ro_leaves(f"{loc}.{k}", v)
            return
        if t == "reasoning":
            self._reasoning(loc, it)
            return
        if t in _SERVER_ITEMS:
            if self._opq(loc, "server_tool"):
                items[i] = {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": notice("server_tool")}],
                }
            return
        if t == "message":
            if "content" in it:
                self._parts(f"{loc}.content", it, "content")
            else:
                self.unparseable.append(loc)
        elif t == "function_call":
            if "arguments" in it:
                self.args(f"{loc}.arguments", it, "arguments")
            else:
                self.unparseable.append(loc)
        elif t in ("function_call_output", "custom_tool_call_output", "local_shell_call_output"):
            if "output" in it:
                self._parts(f"{loc}.output", it, "output")
            else:
                self.unparseable.append(loc)
        elif t == "custom_tool_call":
            if "input" in it:
                self._seg(f"{loc}.input", it, "input")
            else:
                self.unparseable.append(loc)
        elif t in ("local_shell_call", "shell_call"):
            if "action" in it:
                self._leaves(f"{loc}.action", it, "action", _ACTION_SKIP)
        elif t == "shell_call_output":
            if "output" in it:
                self._leaves(f"{loc}.output", it, "output", _OUTCOME_SKIP)
        else:
            self.unparseable.append(loc)
        if t in _ITEM_KEYS:
            self._extra(loc, it, _ITEM_KEYS[t])

    def _reasoning(self, loc: str, it: dict) -> None:
        """Reasoning items are never modified; their summary and content text is scanned read-only."""
        for k, val in it.items():
            if k not in _REASONING_KEYS or (
                k in ("type", "id", "status", "encrypted_content") and isinstance(val, (dict, list))
            ):
                self.unparseable.append(f"{loc}.{k}")
        for key in ("summary", "content"):
            parts = it.get(key)
            if parts is None:
                continue
            if not isinstance(parts, list):
                self.unparseable.append(f"{loc}.{key}")
                continue
            for j, part in enumerate(parts):
                self._ro(f"{loc}.{key}[{j}].text", part, "text")
                if isinstance(part, dict):
                    for k, v in part.items():
                        if k not in _REASONING_PART_KEYS or (
                            k == "type" and isinstance(v, (dict, list))
                        ):
                            self._ro_leaves(f"{loc}.{key}[{j}].{k}", v)

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
                if "description" in tool:
                    self._seg(f"{loc}.description", tool, "description")
                if "parameters" in tool:
                    self._schema(f"{loc}.parameters", tool, "parameters")
                self._extra(loc, tool, _FUNCTION_TOOL_KEYS)
            elif t == "custom":
                self.custom_tool(loc, tool)
            elif self._opq(loc, "server_tool"):
                continue
            keep.append(tool)
        if self.decision is not None:
            tools[:] = keep

    def walk(self, body: dict) -> None:
        if body.get("instructions") is not None:
            self._seg("instructions", body, "instructions")
        if "input" in body:
            inp = body["input"]
            if isinstance(inp, str):
                self._seg("input", body, "input")
            elif isinstance(inp, list):
                for i in range(len(inp)):
                    self._item(f"input[{i}]", inp, i)
            else:
                self.unparseable.append("input")
        if "tools" in body:
            self._tools(body["tools"])
        for k in list(body):
            if k in _HANDLED_KEYS or k in _UNTOUCHED_KEYS:
                continue
            self._leaves(k, body, k)


# Fields of a tool-call output item that identify it rather than say what it runs.
_CALL_IDS = frozenset({"id", "call_id", "type", "status", "name", "encrypted_content"})


def rehydrate_args(args: Any, smap: SessionMap) -> Any:
    """Rehydrate one call's arguments (JSON text, malformed text or an object) as one call."""
    return rehydrate_call_fields({"arguments": args}, smap)["arguments"]


def finish_args(buf: ArgsBuffer, smap: SessionMap) -> str:
    return rehydrate_args("".join(buf._parts), smap)


def rehydrate_item(item: Any, smap: SessionMap) -> Any:
    """Rehydrate one output item. Messages are text; reasoning is untouched; every other item
    (`function_call`, `custom_tool_call`, `*_call`, and any type not known yet) is one tool
    call whose fields share a single egress decision. Unknown types fail closed that way."""
    if not isinstance(item, dict):
        return rehydrate_tree(item, smap)
    t = item.get("type")
    if t == "reasoning":
        return item
    if t == "message" or (t is None and "role" in item):
        return rehydrate_tree(item, smap)
    rest = {k: v for k, v in item.items() if k not in _CALL_IDS}
    return {**item, **rehydrate_call_fields(rest, smap)}


def rehydrate_tree(obj: Any, smap: SessionMap, key: str | None = None) -> Any:
    """Rehydrate string values; reasoning items and encrypted_content stay untouched.

    `arguments` (text or object) and the items of an `output` list are tool calls, decided
    once per call: if any of a call's strings names an outside host, all its placeholders
    are withheld.
    """
    if key == "arguments" and not (isinstance(obj, str) and not obj.strip()):
        return rehydrate_args(obj, smap)
    if key == "output" and isinstance(obj, list):
        return [rehydrate_item(v, smap) for v in obj]
    if isinstance(obj, str):
        return smap.rehydrate(obj)
    if isinstance(obj, list):
        return [rehydrate_tree(v, smap) for v in obj]
    if isinstance(obj, dict):
        t = obj.get("type")
        if t == "reasoning":
            return obj
        if isinstance(t, str) and t.endswith("_call"):
            return rehydrate_item(obj, smap)  # a tool call wherever it appears
        return {
            k: v if k == "encrypted_content" else rehydrate_tree(v, smap, k)
            for k, v in obj.items()
        }
    return obj


class _ResponsesStream:
    def __init__(self, smap: SessionMap) -> None:
        self._smap = smap
        self._text: dict[tuple[Any, Any], tuple[TextHoldback, dict]] = {}
        self._refusal: dict[tuple[Any, Any], tuple[TextHoldback, dict]] = {}
        self._args: dict[Any, ArgsBuffer] = {}
        self._has_args: set[Any] = set()
        self._custom: dict[Any, list[str]] = {}
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
            or any(c for c in self._custom.values())
            or any(hb._pending for hb, _ in self._text.values())
            or any(hb._pending for hb, _ in self._refusal.values())
        )

    @staticmethod
    def _text_event(meta: dict, text: str, t: str = "response.output_text.delta") -> SSEEvent:
        return SSEEvent(t, dump({"type": t, **meta, "delta": text}))

    def _flush(self, match: Any) -> list[SSEEvent]:
        out: list[SSEEvent] = []
        for store, t in (
            (self._text, "response.output_text.delta"),
            (self._refusal, "response.refusal.delta"),
        ):
            for key in [k for k in store if match(k)]:
                hb, meta = store.pop(key)
                tail = hb.flush()
                if tail:
                    self._count(tail)
                    out.append(self._text_event(meta, tail, t))
        return out

    def feed(self, ev: SSEEvent) -> list[SSEEvent]:
        try:
            data = json.loads(ev.data)
        except ValueError as e:
            raise ValueError("unparseable SSE data") from e
        if not isinstance(data, dict):
            raise TypeError("unexpected SSE data shape")
        t = data.get("type")
        if t == "response.output_text.delta":
            return self._text_delta(ev, data, self._text)
        if t == "response.output_text.done":
            out = self._flush(lambda k: k == (data.get("item_id"), data.get("content_index")))
            if isinstance(data.get("text"), str):
                data["text"] = self._smap.rehydrate(data["text"])
            return [*out, SSEEvent(ev.event, dump(data))]
        if t == "response.refusal.delta":
            return self._text_delta(ev, data, self._refusal)
        if t == "response.refusal.done":
            out = self._flush(lambda k: k == (data.get("item_id"), data.get("content_index")))
            if isinstance(data.get("refusal"), str):
                data["refusal"] = self._smap.rehydrate(data["refusal"])
            return [*out, SSEEvent(ev.event, dump(data))]
        if t == "response.output_text.annotation.added":
            if "annotation" in data:
                data["annotation"] = rehydrate_tree(data["annotation"], self._smap)
            return [SSEEvent(ev.event, dump(data))]
        if t == "response.function_call_arguments.delta":
            return self._args_delta(data)
        if t == "response.function_call_arguments.done":
            return self._args_done(ev, data)
        if t == "response.custom_tool_call_input.delta":
            frag = data.get("delta", "")
            self._custom.setdefault(data.get("item_id"), []).append(frag)
            return []
        if t == "response.custom_tool_call_input.done":
            return self._custom_done(ev, data)
        if t in ("response.output_item.added", "response.output_item.done"):
            out = []
            item = data.get("item")
            if t.endswith("done") and isinstance(item, dict):
                out = self._flush(lambda k: k[0] == item.get("id"))
            if "item" in data:
                data["item"] = rehydrate_item(data["item"], self._smap)
            return [*out, SSEEvent(ev.event, dump(data))]
        if t in ("response.content_part.added", "response.content_part.done"):
            out = []
            if t.endswith("done"):
                out = self._flush(lambda k: k == (data.get("item_id"), data.get("content_index")))
            if "part" in data:
                data["part"] = rehydrate_tree(data["part"], self._smap)
            return [*out, SSEEvent(ev.event, dump(data))]
        if t in ("response.completed", "response.incomplete", "response.failed"):
            out = self._flush(lambda k: True)
            if "response" in data:
                data["response"] = rehydrate_tree(data["response"], self._smap)
            return [*out, SSEEvent(ev.event, dump(data))]
        return [ev]

    def _text_delta(self, ev: SSEEvent, data: dict, store: dict) -> list[SSEEvent]:
        key = (data.get("item_id"), data.get("content_index"))
        if key not in store:
            meta = {k: data[k] for k in ("item_id", "output_index", "content_index") if k in data}
            store[key] = (TextHoldback(self._smap), meta)
        out = store[key][0].feed(data.get("delta", ""))
        if not out:
            return []
        self._count(out)
        data["delta"] = out
        return [SSEEvent(ev.event, dump(data))]

    def _args_delta(self, data: dict) -> list[SSEEvent]:
        frag = data.get("delta", "")
        item = data.get("item_id")
        self._args.setdefault(item, ArgsBuffer()).feed(frag)
        if frag.strip():
            self._has_args.add(item)
        return []

    def _args_done(self, ev: SSEEvent, data: dict) -> list[SSEEvent]:
        item = data.get("item_id")
        buf = self._args.pop(item, None)
        buffered = item in self._has_args
        self._has_args.discard(item)
        raw = data.get("arguments")
        if buf is not None and buffered:
            full = finish_args(buf, self._smap)
        elif isinstance(raw, str) and raw.strip():
            full = rehydrate_args(raw, self._smap)
        else:
            return [ev]
        self._count(full)
        t = "response.function_call_arguments.delta"
        meta = {k: data[k] for k in ("item_id", "output_index") if k in data}
        data["arguments"] = full
        return [SSEEvent(t, dump({"type": t, **meta, "delta": full})), SSEEvent(ev.event, dump(data))]

    def _custom_done(self, ev: SSEEvent, data: dict) -> list[SSEEvent]:
        item = data.get("item_id")
        parts = self._custom.pop(item, [])
        raw = data.get("input")
        text = "".join(parts) if "".join(parts).strip() else (raw if isinstance(raw, str) else "")
        if not text.strip():
            return [ev]
        full = self._smap.rehydrate_tool(text)
        self._count(full)
        t = "response.custom_tool_call_input.delta"
        meta = {k: data[k] for k in ("item_id", "output_index") if k in data}
        data["input"] = full
        return [SSEEvent(t, dump({"type": t, **meta, "delta": full})), SSEEvent(ev.event, dump(data))]

    def finish(self) -> list[SSEEvent]:
        out = self._flush(lambda k: True)
        incomplete = len(self._args) + len(self._custom)
        if incomplete:
            self.notes.append(f"incomplete_tool_blocks={incomplete}")
        self._args.clear()  # incomplete tool JSON is never forwarded
        self._has_args.clear()
        self._custom.clear()
        return out


class OpenAIResponsesAdapter:
    format = "openai-responses"
    paths = ("/v1/responses",)
    block_status = 400

    def extract(self, body: dict) -> RequestView:
        w = OpenAIWalker()
        w.walk(body)
        return RequestView(w.segments, w.opaque, w.unparseable, w.readonly)

    def apply(self, body: dict, decision: Decision) -> dict:
        new = copy.deepcopy(body)
        OpenAIWalker(decision).walk(new)
        return new

    def rehydrate_response(self, body: dict, smap: SessionMap) -> dict:
        new = copy.deepcopy(body)
        if "output" in new:
            new["output"] = rehydrate_tree(new["output"], smap, "output")
        return new

    def stream_rewriter(self, smap: SessionMap) -> _ResponsesStream:
        return _ResponsesStream(smap)

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
