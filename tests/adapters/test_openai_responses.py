import copy
import json
from pathlib import Path

from cui_guard.adapters.openai_responses import OpenAIResponsesAdapter
from cui_guard.adapters.sse import SSEEvent
from cui_guard.pipeline import Decision
from cui_guard.pseudo.mapper import SessionMap

FIX = Path(__file__).parent / "fixtures"
AD = OpenAIResponsesAdapter()
NOTICE = "[cui-guard: {} removed — not scannable on this lane]"


def load():
    return json.loads((FIX / "openai_responses_request.json").read_text())


def make_map():
    m = SessionMap()
    m.placeholder_for("db.example.mil", "host")
    return m


def ev(data):
    return SSEEvent(data["type"], json.dumps(data))


def run(datas, smap=None):
    rw = AD.stream_rewriter(smap or make_map())
    out = []
    for d in datas:
        out += rw.feed(ev(d))
    out += rw.finish()
    return rw, [json.loads(e.data) for e in out]


def test_extract_covers_all_strings():
    body = load()
    view = AD.extract(body)
    texts = {s.text for s in view.segments}
    assert not view.unparseable
    expected = {
        "Be terse.", "meta-label-1", "auto", "future note", "plain user text", "part text one",
        "assistant text", "cite title", "refusal words", "/tmp/a", "r", "file contents", "output part",
        "custom input text", "custom output text", "ls", "-la", "shell out", "Read a file",
        "path desc", "enum-a", "answer field", "out", "json_schema",
    }  # fmt: skip
    assert expected <= texts
    assert not {"gpt-5", "low", "reasoning.encrypted_content", "https://mcp.example.mil/sse"} & texts
    assert not {"file-abc", "https://x.example/", "required", "path"} & texts
    assert not any("c2lnLXN5bnRoZXRpYw" in t or "Plan:" in t for t in texts)
    assert [s.index for s in view.segments] == list(range(len(view.segments)))


def test_string_input():
    view = AD.extract({"model": "m", "input": "hello"})
    assert [(s.location, s.text) for s in view.segments] == [("input", "hello")]


def test_reasoning_untouched():
    body = load()
    view = AD.extract(body)
    dec = Decision(replacements={s.index: s.text.upper() for s in view.segments})
    out = AD.apply(body, dec)
    assert json.dumps(out["input"][2]) == json.dumps(body["input"][2])
    assert out["reasoning"] == body["reasoning"] and out["include"] == body["include"]
    assert out["input"][3]["content"][0]["text"] == "ASSISTANT TEXT"
    # function_call arguments re-serialised compactly, structure preserved
    assert json.loads(out["input"][4]["arguments"]) == {"path": "/TMP/A", "opts": {"mode": "R"}, "n": 3}


def test_unknown_item_unparseable():
    body = {"model": "m", "input": [{"type": "message", "role": "user", "content": "x"}, {"type": "future_item"}]}
    assert AD.extract(body).unparseable == ["input[1]"]
    body = {"model": "m", "input": [{"role": "user", "content": [{"type": "input_hologram"}]}]}
    assert AD.extract(body).unparseable == ["input[0].content[0]"]
    body = {"model": "m", "input": [{"type": "function_call", "arguments": "{not json"}]}
    assert AD.extract(body).unparseable == ["input[0].arguments"]


def test_image_part_opaque():
    body = load()
    view = AD.extract(body)
    kinds = sorted(o.kind for o in view.opaque)
    assert kinds == ["document", "image", "server_tool", "server_tool", "server_tool", "url_source"]
    img = next(o for o in view.opaque if o.kind == "image")
    out = AD.apply(body, Decision(replace_opaque={img.index}))
    assert out["input"][1]["content"][1] == {"type": "input_text", "text": NOTICE.format("image")}
    assert body["input"][1]["content"][1]["type"] == "input_image"
    srv = [o for o in view.opaque if o.location.startswith("tools")]
    assert [o.location for o in srv] == ["tools[1]", "tools[2]"]
    assert len(AD.apply(body, Decision())["tools"]) == 3
    out = AD.apply(body, Decision(replace_opaque={o.index for o in srv}))
    assert [t["name"] for t in out["tools"]] == ["read_file"]
    ws = next(o for o in view.opaque if o.location == "input[11]")
    out = AD.apply(body, Decision(replace_opaque={ws.index}))
    assert out["input"][11]["content"][0]["text"] == NOTICE.format("server_tool")


def test_apply_preserves_structure():
    body = load()
    before = copy.deepcopy(body)
    view = AD.extract(body)
    out = AD.apply(body, Decision(replacements={s.index: "X" for s in view.segments}))
    assert body == before
    assert list(out) == list(body) and len(out["input"]) == len(body["input"])
    assert AD.apply(body, Decision()) == body


def test_rehydrate_response_skips_reasoning():
    smap = make_map()
    ph = smap.placeholder_for("db.example.mil", "host")
    resp = {
        "id": "r",
        "output": [
            {"type": "reasoning", "encrypted_content": ph, "summary": [{"text": ph}]},
            {"type": "message", "content": [{"type": "output_text", "text": f"see {ph}"}]},
            {"type": "function_call", "arguments": json.dumps({"h": ph})},
        ],
    }
    out = AD.rehydrate_response(resp, smap)
    assert out["output"][0] == resp["output"][0]
    assert out["output"][1]["content"][0]["text"] == "see db.example.mil"
    assert json.loads(out["output"][2]["arguments"]) == {"h": "db.example.mil"}


def test_stream_text_rehydrated():
    smap = make_map()
    ph = smap.placeholder_for("db.example.mil", "host")
    base = {"item_id": "m1", "output_index": 0, "content_index": 0}
    datas = [
        {"type": "response.output_item.added", "output_index": 0, "item": {"id": "m1", "type": "message", "content": []}},
        {"type": "response.output_text.delta", **base, "delta": "the host "},
        {"type": "response.output_text.delta", **base, "delta": ph[:4]},
        {"type": "response.output_text.delta", **base, "delta": ph[4:9]},
        {"type": "response.output_text.delta", **base, "delta": ph[9:] + " is up"},
        {"type": "response.output_text.done", **base, "text": f"the host {ph} is up"},
        {"type": "response.output_item.done", "output_index": 0, "item": {"id": "m1", "type": "message", "content": [{"type": "output_text", "text": f"x {ph}"}]}},
        {"type": "response.completed", "response": {"output": [
            {"type": "reasoning", "encrypted_content": ph},
            {"type": "message", "content": [{"type": "output_text", "text": ph}]},
        ]}},
        {"type": "response.future_event", "payload": ph},
    ]  # fmt: skip
    rw, out = run(datas, smap)
    text = "".join(d["delta"] for d in out if d["type"] == "response.output_text.delta")
    assert text == "the host db.example.mil is up"
    done = next(d for d in out if d["type"] == "response.output_text.done")
    assert done["text"] == "the host db.example.mil is up"
    assert next(d for d in out if d["type"] == "response.output_item.done")["item"]["content"][0]["text"] == "x db.example.mil"
    comp = next(d for d in out if d["type"] == "response.completed")["response"]["output"]
    assert comp[0]["encrypted_content"] == ph and comp[1]["content"][0]["text"] == "db.example.mil"
    assert out[-1] == {"type": "response.future_event", "payload": ph}  # unknown events untouched
    assert not rw.pending and rw.notes == []


def test_stream_text_flushed_on_done():
    smap = make_map()
    base = {"item_id": "m1", "output_index": 0, "content_index": 0}
    rw, out = run(
        [
            {"type": "response.output_text.delta", **base, "delta": "tail CG_"},
            {"type": "response.output_text.done", **base, "text": "tail CG_"},
        ],
        smap,
    )
    assert "".join(d["delta"] for d in out if d["type"].endswith("delta")) == "tail CG_"
    assert out[-1]["type"] == "response.output_text.done"
    assert rw.notes == []


def test_stream_args_single_emit_rehydrated():
    smap = make_map()
    ph = smap.placeholder_for("db.example.mil", "host")
    full = json.dumps({"host": ph})
    item = {"item_id": "fc1", "output_index": 1}
    rw = AD.stream_rewriter(smap)
    out = []
    for frag in (full[:5], full[5:12], full[12:]):
        out += rw.feed(ev({"type": "response.function_call_arguments.delta", **item, "delta": frag}))
    assert out == [] and rw.pending
    out = rw.feed(ev({"type": "response.function_call_arguments.done", **item, "arguments": full}))
    datas = [json.loads(e.data) for e in out]
    assert [d["type"] for d in datas] == [
        "response.function_call_arguments.delta",
        "response.function_call_arguments.done",
    ]
    assert json.loads(datas[0]["delta"]) == {"host": "db.example.mil"}
    assert datas[1]["arguments"] == datas[0]["delta"]
    assert not rw.pending and rw.finish() == []


def test_stream_custom_tool_input():
    smap = make_map()
    ph = smap.placeholder_for("db.example.mil", "host")
    item = {"item_id": "ct1", "output_index": 0}
    _rw, out = run(
        [
            {"type": "response.custom_tool_call_input.delta", **item, "delta": "ping "},
            {"type": "response.custom_tool_call_input.delta", **item, "delta": ph},
            {"type": "response.custom_tool_call_input.done", **item, "input": f"ping {ph}"},
        ],
        smap,
    )
    assert [d["type"] for d in out] == [
        "response.custom_tool_call_input.delta",
        "response.custom_tool_call_input.done",
    ]
    assert out[0]["delta"] == out[1]["input"] == "ping db.example.mil"


def test_incomplete_args_dropped_and_noted():
    rw, out = run([{"type": "response.function_call_arguments.delta", "item_id": "a", "delta": '{"x":'}])
    assert out == [] and rw.notes == ["incomplete_tool_blocks=1"]


def test_keepalive_and_error_body():
    assert AD.keepalive() == b": keepalive\n\n"
    assert AD.error_body("m") == {
        "error": {"message": "m", "type": "invalid_request_error", "code": "cui_guard_blocked"}
    }
    assert AD.block_status == 400 and AD.paths == ("/v1/responses",) and AD.format == "openai-responses"


def test_shell_action_all_strings_except_type():
    body = {"model": "m", "input": [
        {"type": "local_shell_call", "call_id": "c", "action": {
            "type": "exec", "command": ["ls"], "env": {"K": "env-val"}, "working_directory": "/work", "user": "bob"}},
        {"type": "shell_call", "call_id": "d", "action": {"commands": ["pwd"], "timeout_ms": 5}},
    ]}  # fmt: skip
    texts = {s.text for s in AD.extract(body).segments}
    assert texts == {"ls", "env-val", "/work", "bob", "pwd"}


def test_stream_malformed_args_fall_back_to_string_rehydrate():
    smap = make_map()
    ph = smap.placeholder_for("db.example.mil", "host")
    bad = '{"h": ' + ph + " oops"
    item = {"item_id": "fc1", "output_index": 0}
    rw = AD.stream_rewriter(smap)
    rw.feed(ev({"type": "response.function_call_arguments.delta", **item, "delta": bad}))
    out = [json.loads(e.data) for e in rw.feed(ev({"type": "response.function_call_arguments.done", **item, "arguments": bad}))]
    assert out[0]["delta"] == out[1]["arguments"] == '{"h": db.example.mil oops'
    # done without any delta, and a completed payload
    out = [json.loads(e.data) for e in rw.feed(ev({"type": "response.function_call_arguments.done", "item_id": "z", "arguments": bad}))]
    assert out[1]["arguments"] == '{"h": db.example.mil oops'
    _rw, outs = run([{"type": "response.completed", "response": {"output": [{"type": "function_call", "arguments": bad}]}}], smap)
    assert outs[0]["response"]["output"][0]["arguments"] == '{"h": db.example.mil oops'


def test_stream_refusal_and_annotation_and_failed():
    smap = make_map()
    ph = smap.placeholder_for("db.example.mil", "host")
    base = {"item_id": "m1", "output_index": 0, "content_index": 0}
    rw, out = run(
        [
            {"type": "response.refusal.delta", **base, "delta": "no " + ph[:5]},
            {"type": "response.refusal.delta", **base, "delta": ph[5:] + " ok"},
            {"type": "response.refusal.done", **base, "refusal": f"no {ph} ok"},
            {"type": "response.output_text.annotation.added", **base, "annotation": {"type": "url_citation", "title": ph}},
            {"type": "response.output_text.delta", **base, "delta": "held CG_"},
            {"type": "response.failed", "response": {"output": [{"type": "message", "content": [{"type": "output_text", "text": ph}]}]}},
        ],
        smap,
    )  # fmt: skip
    ref = "".join(d["delta"] for d in out if d["type"] == "response.refusal.delta")
    assert ref == "no db.example.mil ok"
    assert next(d for d in out if d["type"] == "response.refusal.done")["refusal"] == "no db.example.mil ok"
    assert next(d for d in out if d["type"].endswith("annotation.added"))["annotation"]["title"] == "db.example.mil"
    types = [d["type"] for d in out]
    assert types[-2:] == ["response.output_text.delta", "response.failed"]  # held text flushed before failed
    assert out[-1]["response"]["output"][0]["content"][0]["text"] == "db.example.mil"
    assert not rw.pending
