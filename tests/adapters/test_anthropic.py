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
STRUCTURAL = {"type", "role", "id", "name", "tool_use_id", "model", "media_type", "data", "url", "required"}
SKIP_TYPES = {"thinking", "redacted_thinking", "server_tool_use", "web_search_tool_result", "image", "document"}


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


def free_strings(obj, key=None):
    if isinstance(obj, str):
        if key not in STRUCTURAL:
            yield obj
    elif isinstance(obj, list):
        for v in obj:
            yield from free_strings(v, key)
    elif isinstance(obj, dict):
        if obj.get("type") in SKIP_TYPES:
            return
        if obj.get("type", "").startswith("web_search_2"):
            return
        for k, v in obj.items():
            yield from free_strings(v, k)


def test_extract_covers_all_strings():
    body = load("anthropic_request.json")
    view = AD.extract(body)
    texts = {s.text for s in view.segments}
    assert not view.unparseable
    expected = set(free_strings(body))
    expected.discard("ephemeral")  # cache_control value, not content
    assert expected <= texts
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
    assert kinds == ["encrypted", "image", "server_tool", "server_tool", "url_source"]
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
