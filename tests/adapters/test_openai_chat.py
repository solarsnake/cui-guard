import copy
import json
from pathlib import Path

from cui_guard.adapters.openai_chat import OpenAIChatAdapter
from cui_guard.adapters.sse import SSEEvent
from cui_guard.pipeline import Decision
from cui_guard.pseudo.mapper import SessionMap

FIX = Path(__file__).parent / "fixtures"
AD = OpenAIChatAdapter()
NOTICE = "[cui-guard: {} removed — not scannable on this lane]"
HOST = "db.example.mil"


def load():
    return json.loads((FIX / "openai_chat_request.json").read_text())


def make_map():
    m = SessionMap()
    m.placeholder_for(HOST, "host")
    return m


def chunk(delta, finish=None, idx=0):
    return {
        "id": "c1", "object": "chat.completion.chunk", "model": "m",
        "choices": [{"index": idx, "delta": delta, "finish_reason": finish}],
    }  # fmt: skip


def run(items, smap=None):
    """items: dicts (JSON chunks) or the string [DONE]."""
    rw = AD.stream_rewriter(smap or make_map())
    out = []
    for it in items:
        data = it if isinstance(it, str) else json.dumps(it)
        out += rw.feed(SSEEvent(None, data))
    out += rw.finish()
    return rw, out


def test_extract_covers_all_strings():
    body = load()
    view = AD.extract(body)
    texts = {s.text for s in view.segments}
    assert not view.unparseable
    expected = {
        "STOPWORD", "meta-label-1", "future note", "Be terse.", "plain user text", "part text one",
        "refusal words", "my reasoning", "/tmp/a", "r", "file contents", "tool part", "Read a file",
        "path desc", "enum-a", "answer field", "out", "json_schema",
    }  # fmt: skip
    assert expected <= texts
    assert not {"llama3", "alice", "call_1", "assistant", "user", "file-abc", "path", "required"} & texts
    assert [s.index for s in view.segments] == list(range(len(view.segments)))


def test_apply_rewrites_strings_only():
    body = load()
    before = copy.deepcopy(body)
    view = AD.extract(body)
    out = AD.apply(body, Decision(replacements={s.index: s.text.upper() for s in view.segments}))
    assert body == before
    assert out["messages"][1]["name"] == "alice"
    args = out["messages"][3]["tool_calls"][0]["function"]["arguments"]
    assert json.loads(args) == {"path": "/TMP/A", "opts": {"mode": "R"}, "n": 3}
    assert AD.apply(body, Decision()) == body


def test_unknown_item_unparseable():
    body = {"model": "m", "messages": [{"role": "user", "content": [{"type": "hologram"}]}]}
    assert AD.extract(body).unparseable == ["messages[0].content[0]"]
    body = {"model": "m", "messages": [{"role": "assistant", "tool_calls": [
        {"id": "x", "type": "function", "function": {"name": "f", "arguments": "{bad"}}]}]}  # fmt: skip
    assert AD.extract(body).unparseable == ["messages[0].tool_calls[0].function.arguments"]
    assert AD.extract({"model": "m", "messages": ["x"]}).unparseable == ["messages[0]"]


def test_image_part_opaque():
    body = load()
    view = AD.extract(body)
    assert sorted(o.kind for o in view.opaque) == ["document", "image", "url_source"]
    img = next(o for o in view.opaque if o.kind == "image")
    out = AD.apply(body, Decision(replace_opaque={img.index}))
    assert out["messages"][2]["content"][1] == {"type": "text", "text": NOTICE.format("image")}
    assert body["messages"][2]["content"][1]["type"] == "image_url"


def test_server_tool_opaque():
    body = {"model": "m", "messages": [], "tools": [{"type": "web_search"}, {"type": "function", "function": {"name": "f"}}]}
    view = AD.extract(body)
    assert [(o.location, o.kind) for o in view.opaque] == [("tools[0]", "server_tool")]
    out = AD.apply(body, Decision(replace_opaque={0}))
    assert [t["type"] for t in out["tools"]] == ["function"]


def test_rehydrate_response():
    smap = make_map()
    ph = smap.placeholder_for(HOST, "host")
    resp = {"choices": [{"index": 0, "message": {
        "role": "assistant", "content": f"see {ph}",
        "tool_calls": [{"id": "1", "type": "function", "function": {"name": "f", "arguments": json.dumps({"h": ph})}}],
    }}]}  # fmt: skip
    out = AD.rehydrate_response(resp, smap)
    msg = out["choices"][0]["message"]
    assert msg["content"] == f"see {HOST}"
    assert json.loads(msg["tool_calls"][0]["function"]["arguments"]) == {"h": HOST}


def test_stream_text_rehydrated():
    smap = make_map()
    ph = smap.placeholder_for(HOST, "host")
    items = [
        chunk({"role": "assistant", "content": ""}),
        chunk({"content": "the host "}),
        chunk({"content": ph[:4]}),
        chunk({"content": ph[4:9]}),
        chunk({"content": ph[9:]}),
        chunk({"content": " is up"}, finish="stop"),
        "[DONE]",
    ]
    rw, out = run(items, smap)
    datas = [json.loads(e.data) for e in out if e.data != "[DONE]"]
    text = "".join(d["choices"][0]["delta"].get("content") or "" for d in datas)
    assert text == f"the host {HOST} is up"
    assert datas[-1]["choices"][0]["finish_reason"] == "stop"
    assert not rw.pending and rw.notes == []


def test_stream_holdback_flushed_in_final_chunk():
    _rw, out = run([chunk({"content": "tail CG_"}), chunk({}, finish="stop")])
    datas = [json.loads(e.data) for e in out]
    assert "".join(d["choices"][0]["delta"].get("content", "") for d in datas) == "tail CG_"
    assert datas[-1]["choices"][0]["finish_reason"] == "stop"


def test_stream_args_single_emit_rehydrated():
    smap = make_map()
    ph = smap.placeholder_for(HOST, "host")
    full = json.dumps({"host": ph})

    def tc(args, **extra):
        return chunk({"tool_calls": [{"index": 0, "function": {"arguments": args}, **extra}]})

    first = chunk({"tool_calls": [{"index": 0, "id": "call_1", "type": "function", "function": {"name": "f", "arguments": ""}}]})
    rw = AD.stream_rewriter(smap)
    out = rw.feed(SSEEvent(None, json.dumps(first)))
    assert json.loads(out[0].data)["choices"][0]["delta"]["tool_calls"][0]["id"] == "call_1"
    for frag in (full[:5], full[5:12], full[12:]):
        assert rw.feed(SSEEvent(None, json.dumps(tc(frag)))) == []
    assert rw.pending
    out = rw.feed(SSEEvent(None, json.dumps(chunk({}, finish="tool_calls"))))
    datas = [json.loads(e.data) for e in out]
    assert len(datas) == 2
    emitted = datas[0]["choices"][0]["delta"]["tool_calls"]
    assert len(emitted) == 1 and json.loads(emitted[0]["function"]["arguments"]) == {"host": HOST}
    assert datas[0]["choices"][0]["finish_reason"] is None
    assert datas[1]["choices"][0]["finish_reason"] == "tool_calls"
    assert not rw.pending and rw.finish() == []


def test_done_sentinel_passthrough():
    rw = AD.stream_rewriter(make_map())
    ev = SSEEvent(None, "[DONE]")
    assert rw.feed(ev) == [ev]
    usage = SSEEvent(None, json.dumps({"id": "c", "choices": [], "usage": {"total_tokens": 3}}))
    assert [json.loads(e.data) for e in rw.feed(usage)] == [json.loads(usage.data)]


def test_incomplete_args_dropped_and_noted():
    rw, out = run([chunk({"tool_calls": [{"index": 0, "function": {"arguments": '{"x":'}}]})])
    assert out == [] and rw.notes == ["incomplete_tool_blocks=1"]


def test_keepalive_and_error_body():
    assert AD.keepalive() == b": keepalive\n\n"
    assert AD.error_body("m")["error"]["code"] == "cui_guard_blocked"
    assert AD.block_status == 400 and AD.paths == ("/v1/chat/completions",) and AD.format == "openai-chat"
