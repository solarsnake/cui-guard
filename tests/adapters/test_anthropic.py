import copy
import json
from pathlib import Path

from cui_guard.adapters.anthropic import AnthropicAdapter
from cui_guard.adapters.sse import SSEDecoder, SSEEvent
from cui_guard.pipeline import Decision
from cui_guard.pseudo.mapper import SessionMap

FIX = Path(__file__).parent / "fixtures"
AD = AnthropicAdapter()
NOTICE = "[cui-guard: {} removed — not scannable on this lane]"
UNTOUCHED_TOP = {"model", "max_tokens", "stream", "temperature", "top_p", "top_k", "thinking", "mcp_servers"}
SKIP_KEYS = {
    "type", "role", "id", "tool_use_id", "name", "media_type", "required", "$ref", "$schema", "format",
    "additionalProperties", "cache_control", "file_id", "url",
}  # fmt: skip
OPAQUE_TYPES = {"thinking", "redacted_thinking", "server_tool_use", "web_search_tool_result", "image"}


def load(name):
    return json.loads((FIX / name).read_text())


def make_map():
    m = SessionMap()
    m.placeholder_for("db.example.mil", "host")
    m.placeholder_for("Jane", "person")
    return m


def events(name):
    return SSEDecoder().feed((FIX / name).read_bytes())


def run(name, smap=None):
    rw = AD.stream_rewriter(smap or make_map())
    out = []
    for ev in events(name):
        out += rw.feed(ev)
    out += rw.finish()
    return rw, out


def payloads(evs):
    return [json.loads(e.data) for e in evs]


def free_strings(obj, key=None, top=True):
    """Strings that must be covered by a segment."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, list):
        for v in obj:
            yield from free_strings(v, key, False)
    elif isinstance(obj, dict):
        t = obj.get("type")
        if t in OPAQUE_TYPES or (key == "tools" and t not in (None, "custom")):
            return
        if t == "document" and obj["source"]["type"] in ("base64", "url", "file"):
            for k in ("title", "context"):
                yield from free_strings(obj.get(k), k, False)
            return
        for k, v in obj.items():
            if k in SKIP_KEYS or (top and k in UNTOUCHED_TOP):
                continue
            yield from free_strings(v, k, False)


def test_extract_covers_all_strings():
    body = load("anthropic_request.json")
    view = AD.extract(body)
    texts = {s.text for s in view.segments}
    assert not view.unparseable
    expected = set(free_strings(body))
    assert {"STOPWORD", "user-label-1", "future note", "kb-source-one", "T2", "Doc T", "ctx here",
            "doc body text", "inner doc text", "cited words", "Doc A", "boom", "The answer text"} <= expected  # fmt: skip
    assert expected <= texts
    assert not {"claude-sonnet-4-5", "https://mcp.example.mil/sse", "ephemeral"} & texts
    assert not any("c2lnLXN5bnRoZXRpYw" in t or "Plan:" in t for t in texts)
    assert [s.index for s in view.segments] == list(range(len(view.segments)))


def test_thinking_untouched_round_trip():
    body = load("anthropic_request.json")
    view = AD.extract(body)
    dec = Decision(replacements={s.index: s.text.upper() for s in view.segments})
    out = AD.apply(body, dec)
    orig = body["messages"][1]["content"]
    new = out["messages"][1]["content"]
    for i in (0, 1):
        assert json.dumps(new[i]) == json.dumps(orig[i])
    assert new[2]["text"] == "READING THE LOG."


def test_unknown_block_unparseable():
    view = AD.extract(load("anthropic_unknown_block.json"))
    assert view.unparseable == ["messages[0].content[1]"]


def test_image_replaced_text_notice():
    body = load("anthropic_request.json")
    view = AD.extract(body)
    img = next(o for o in view.opaque if o.kind == "image")
    out = AD.apply(body, Decision(replace_opaque={img.index}))
    assert out["messages"][2]["content"][0]["content"][1] == {"type": "text", "text": NOTICE.format("image")}
    assert body["messages"][2]["content"][0]["content"][1]["type"] == "image"  # input not mutated


def test_url_document_source_is_opaque():
    body = load("anthropic_request.json")
    view = AD.extract(body)
    kinds = sorted(o.kind for o in view.opaque)
    assert kinds == ["document", "encrypted", "image", "image", "server_tool", "server_tool", "server_tool", "url_source"]
    doc = next(o for o in view.opaque if o.kind == "url_source")
    out = AD.apply(body, Decision(replace_opaque={doc.index}))
    assert out["messages"][2]["content"][2]["text"] == NOTICE.format("url_source")
    # server tool entry removed from tools only when selected
    srv_tool = next(o for o in view.opaque if o.location == "tools[1]")
    assert len(AD.apply(body, Decision())["tools"]) == 2
    assert [t["name"] for t in AD.apply(body, Decision(replace_opaque={srv_tool.index}))["tools"]] == ["read_file"]
    enc = next(o for o in view.opaque if o.kind == "encrypted")
    out = AD.apply(body, Decision(replace_opaque={enc.index}))
    assert out["messages"][1]["content"][5]["text"] == NOTICE.format("encrypted")


def test_apply_preserves_structure():
    body = load("anthropic_request.json")
    before = copy.deepcopy(body)
    view = AD.extract(body)
    out = AD.apply(body, Decision(replacements={s.index: "X" for s in view.segments}))
    assert body == before

    def shape(o):
        if isinstance(o, dict):
            return [(k, shape(v)) for k, v in o.items()]
        if isinstance(o, list):
            return [shape(v) for v in o]
        return "s" if isinstance(o, str) else o

    # keys and order identical; only string values differ
    assert shape(out["messages"]) == shape(before["messages"])
    assert shape(out["system"]) == shape(before["system"])
    assert out["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert out["messages"][2]["content"][3]["cache_control"] == {"type": "ephemeral"}
    assert out["messages"][0]["content"] == "X"
    assert out["tools"][0]["input_schema"]["properties"]["path"]["description"] == "X"
    assert out["tools"][0]["name"] == "read_file"
    assert list(out) == list(before)
    inp = out["messages"][1]["content"][3]["input"]
    assert list(inp) == ["path", "opts"] and inp["opts"]["tags"] == ["X", "X"] and inp["opts"]["n"] == 3


def test_string_system_stays_string():
    body = {"model": "m", "system": "sys db.example.mil", "messages": [{"role": "user", "content": "hi"}]}
    view = AD.extract(body)
    assert [s.text for s in view.segments] == ["sys db.example.mil", "hi"]
    out = AD.apply(body, Decision(replacements={0: "sys host-01.cg.invalid"}))
    assert out["system"] == "sys host-01.cg.invalid"


def test_rehydrate_nonstream_text_and_tool_input():
    out = AD.rehydrate_response(load("anthropic_response.json"), make_map())
    assert out["content"][1]["text"] == "The server is db.example.mil, owner Jane."
    assert out["content"][2]["input"] == {"path": "/srv/db.example.mil/log", "who": ["Jane"]}
    assert out["content"][0] == load("anthropic_response.json")["content"][0]


def test_stream_text_rehydrated():
    rw, out = run("anthropic_stream_text.sse")
    deltas = [p for p in payloads(out) if p["type"] == "content_block_delta"]
    text = "".join(p["delta"]["text"] for p in deltas)
    assert text == "Server db.example.mil is up, ask Jane. Also CG_PERSON_77."
    assert rw.notes == ["leftover_placeholders=1"]
    assert "CG_PERSON_77" not in " ".join(rw.notes)
    assert [e.event for e in out if e.event in ("ping", "message_start", "message_stop")] == [
        "message_start",
        "ping",
        "message_stop",
    ]


def test_placeholder_split_across_deltas_rehydrated():
    rw, out = run("anthropic_stream_split.sse")
    text = "".join(p["delta"]["text"] for p in payloads(out) if p["type"] == "content_block_delta")
    assert text == "see db.example.mil now"
    assert "host-0" not in json.dumps(payloads(out))
    assert out[-1].event == "content_block_stop"
    assert rw.notes == []


def test_stream_tool_input_single_delta_at_stop():
    _, out = run("anthropic_stream_tool.sse")
    ps = payloads(out)
    by_idx = {}
    for i, p in enumerate(ps):
        if p["type"] == "content_block_delta":
            by_idx.setdefault(p["index"], []).append((i, p))
    assert [p["delta"]["type"] for _, p in by_idx[1]] == ["input_json_delta"]
    pos, p = by_idx[1][0]
    assert json.loads(p["delta"]["partial_json"]) == {"path": "/srv/db.example.mil/log", "who": ["Jane"]}
    assert ps[pos + 1] == {"type": "content_block_stop", "index": 1}
    assert 2 not in by_idx  # no-arg tool: nothing extra emitted
    assert ps[0]["content_block"]["input"] == {}


def test_stream_thinking_and_signature_passthrough():
    src = events("anthropic_stream_thinking.sse")
    rw = AD.stream_rewriter(make_map())
    out = []
    for ev in src:
        out += rw.feed(ev)
    out += rw.finish()
    assert [(e.event, e.data) for e in out] == [(e.event, e.data) for e in src]
    assert isinstance(out[0], SSEEvent)


def test_error_body_and_attrs():
    assert AD.error_body("no") == {"type": "error", "error": {"type": "invalid_request_error", "message": "no"}}
    assert (AD.format, AD.paths, AD.block_status) == ("anthropic", ("/v1/messages",), 400)


def test_mcp_servers_opaque_removed_when_replaced():
    body = load("anthropic_request.json")
    view = AD.extract(body)
    mcp = next(o for o in view.opaque if o.location == "mcp_servers")
    assert mcp.kind == "server_tool"
    assert "mcp_servers" in AD.apply(body, Decision())
    assert "mcp_servers" not in AD.apply(body, Decision(replace_opaque={mcp.index}))


def test_document_text_sources_segments_base64_opaque():
    body = load("anthropic_request.json")
    view = AD.extract(body)
    locs = {s.location for s in view.segments}
    assert {"messages[2].content[5].source.data", "messages[2].content[5].title",
            "messages[2].content[5].context", "messages[2].content[6].source.content[0].text",
            "messages[2].content[4].title", "messages[2].content[4].source"} <= locs  # fmt: skip
    assert "messages[2].content[7]" in {o.location for o in view.opaque if o.kind == "document"}
    assert not view.unparseable


def test_tool_result_null_content_not_unparseable():
    body = {"model": "m", "messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t", "content": None},
        {"type": "tool_result", "tool_use_id": "u"}]}]}  # fmt: skip
    assert AD.extract(body).unparseable == []


def test_schema_structural_keywords_and_property_names():
    body = {"model": "m", "messages": [], "tools": [{"name": "t", "description": "d", "input_schema": {
        "type": "object", "required": ["type"], "$ref": "#/x",
        "properties": {"type": {"type": "string", "description": "kind", "enum": ["fa", "fb"]}}}}]}  # fmt: skip
    texts = [s.text for s in AD.extract(body).segments]
    assert texts == ["d", "kind", "fa", "fb"]


def test_rehydrate_citations_and_server_tool_input():
    resp = {"content": [
        {"type": "text", "text": "x", "citations": [
            {"type": "char_location", "cited_text": "see host-01.cg.invalid", "document_title": "CG_PERSON_01"}]},
        {"type": "server_tool_use", "id": "s", "name": "web_search", "input": {"query": "host-01.cg.invalid"}},
    ]}  # fmt: skip
    out = AD.rehydrate_response(resp, make_map())
    assert out["content"][0]["citations"][0]["cited_text"] == "see db.example.mil"
    assert out["content"][0]["citations"][0]["document_title"] == "Jane"
    assert out["content"][1]["input"] == {"query": "db.example.mil"}


def test_stream_citations_delta_rehydrated():
    cit = {"type": "char_location", "cited_text": "at host-01.cg.invalid", "document_title": "CG_PERSON_01"}
    ev = SSEEvent("content_block_delta", json.dumps(
        {"type": "content_block_delta", "index": 0, "delta": {"type": "citations_delta", "citation": cit}}))  # fmt: skip
    out = AD.stream_rewriter(make_map()).feed(ev)
    c = json.loads(out[0].data)["delta"]["citation"]
    assert c["cited_text"] == "at db.example.mil" and c["document_title"] == "Jane"


def test_finish_reports_incomplete_tool_blocks():
    rw = AD.stream_rewriter(make_map())
    for ev in events("anthropic_stream_tool.sse")[:3]:  # start + two deltas, no stop
        assert rw.feed(ev) == ([ev] if ev.event == "content_block_start" else [])
    assert rw.finish() == []
    assert rw.notes == ["incomplete_tool_blocks=1"]


def test_tool_input_keys_not_rehydrated():
    """Keys are never scanned outbound, so the agent gets placeholder keys back unchanged (I2)."""
    resp = {"content": [{"type": "tool_use", "id": "t", "name": "run",
                         "input": {"host-01.cg.invalid": "x", "v": {"CG_PERSON_01": "host-01.cg.invalid"}}}]}  # fmt: skip
    out = AD.rehydrate_response(resp, make_map())
    assert out["content"][0]["input"] == {"host-01.cg.invalid": "x", "v": {"CG_PERSON_01": "db.example.mil"}}
    args = json.dumps({"host-01.cg.invalid": "host-01.cg.invalid"})
    evs = [
        SSEEvent("content_block_start", json.dumps({"type": "content_block_start", "index": 0,
                 "content_block": {"type": "tool_use", "id": "t", "name": "run", "input": {}}})),
        SSEEvent("content_block_delta", json.dumps({"type": "content_block_delta", "index": 0,
                 "delta": {"type": "input_json_delta", "partial_json": args}})),
        SSEEvent("content_block_stop", json.dumps({"type": "content_block_stop", "index": 0})),
    ]  # fmt: skip
    rw = AD.stream_rewriter(make_map())
    out_evs = [o for ev in evs for o in rw.feed(ev)]
    full = next(p for p in payloads(out_evs) if p["type"] == "content_block_delta")
    assert json.loads(full["delta"]["partial_json"]) == {"host-01.cg.invalid": "db.example.mil"}


def test_thinking_text_scanned_read_only():
    """Thinking and redacted_thinking text is exposed read-only, never as a rewritable segment (I1)."""
    body = load("anthropic_request.json")
    view = AD.extract(body)
    ro = [(s.location, s.text) for s in view.readonly]
    assert ro == [
        ("messages[1].content[0].thinking", "Plan: read the log."),
        ("messages[1].content[1].data", "cmVkYWN0ZWQ="),
    ]
    assert [s.index for s in view.readonly] == [0, 1]
    bad = {"model": "m", "messages": [{"role": "assistant", "content": [
        {"type": "thinking", "signature": "c2ln"}, {"type": "redacted_thinking", "data": 5}]}]}  # fmt: skip
    assert AD.extract(bad).unparseable == ["messages[0].content[0].thinking", "messages[0].content[1].data"]
