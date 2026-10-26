"""Canary leak suite: real gateway subprocess, real HTTP, recording fake upstream."""

import json
import re

import pytest
from canaries import (
    CANARIES,
    FORMATS,
    KIND_CLASS,
    LOCATIONS,
    PATHS,
    build,
    carrier,
    image_b64,
)
from harness import text_response, tool_call_response

from cui_guard.pseudo.mapper import PLACEHOLDER_RE

TRUSTS = ("public", "approved", "local")
STREAMS = (False, True)
SECRET_KINDS = [k for k, c in KIND_CLASS.items() if c == "secret"]
# Kinds never forwarded at all, per lane trust (spec 3.4 baseline).
BLOCKED = {
    "public": {"cui", "controlled", "classified"},
    "approved": {"classified"},
    "local": {"classified"},
}


def matrix(trusts=TRUSTS):
    return pytest.mark.parametrize(
        "fmt,stream,trust",
        [(f, s, t) for f in FORMATS for s in STREAMS for t in trusts],
        ids=lambda v: str(v),
    )


def send(gw, fmt, body):
    return gw.post(PATHS[fmt], body)


@matrix()
@pytest.mark.parametrize("kind", list(CANARIES))
def test_no_canary_reaches_public_upstream(gateways, upstream, fmt, stream, trust, kind):
    gw = gateways(trust)
    needle = CANARIES[kind]
    for loc in LOCATIONS:
        upstream.reset()
        resp = send(gw, fmt, build(fmt, loc, carrier(kind), stream))
        where = f"{fmt}/{'sse' if stream else 'json'}/{trust}/{kind}@{loc}"
        if kind in BLOCKED[trust]:
            assert upstream.records == [], f"request was forwarded: {where}"
            assert resp.status_code >= 400, where
            continue
        assert resp.status_code == 200, where
        assert len(upstream.records) == 1, where
        sent = upstream.all_bytes()
        if kind in SECRET_KINDS or (trust == "public" and KIND_CLASS[kind] == "identifier"):
            assert needle.encode() not in sent, f"raw canary reached the upstream: {where}"
            assert PLACEHOLDER_RE.search(sent.decode()), f"no placeholder sent: {where}"


@matrix()
def test_combined_canaries(gateways, upstream, fmt, stream, trust):
    """Every non-classified canary in one request, at each location."""
    gw = gateways(trust)
    text = "\n".join(carrier(k) for k in CANARIES if k != "classified")
    for loc in LOCATIONS:
        upstream.reset()
        resp = send(gw, fmt, build(fmt, loc, text, stream))
        if trust == "public":
            assert upstream.records == [], f"forwarded at {loc}"
            assert resp.status_code >= 400
        else:
            assert len(upstream.records) == 1
            sent = upstream.all_bytes().decode()
            for kind in SECRET_KINDS:
                assert CANARIES[kind] not in sent, f"{kind} leaked at {loc}"


@matrix()
def test_classified_never_forwarded_any_lane(gateways, upstream, fmt, stream, trust):
    gw = gateways(trust)
    mixed = carrier("classified") + "\n" + carrier("host") + carrier("secret_aws")
    for text in (carrier("classified"), mixed):
        for loc in LOCATIONS:
            upstream.reset()
            resp = send(gw, fmt, build(fmt, loc, text, stream))
            assert upstream.records == [], f"classified canary forwarded at {loc}"
            assert resp.status_code >= 400


@matrix(("public",))
@pytest.mark.parametrize("kind", ["cui", "host", "secret_aws", "classified"])
def test_image_replaced_by_notice_on_public(gateways, upstream, fmt, stream, trust, kind):
    gw = gateways(trust)
    resp = send(gw, fmt, build(fmt, "image", carrier(kind), stream))
    assert resp.status_code == 200
    sent = upstream.all_bytes().decode()
    assert image_b64(carrier(kind)) not in sent
    assert CANARIES[kind] not in sent
    assert "[cui-guard:" in sent and "removed" in sent


@matrix(("approved", "local"))
@pytest.mark.parametrize("kind", ["secret_aws", "secret_anthropic"])
def test_image_forwarded_uninspected_on_approved_and_local(
    gateways, upstream, fmt, stream, trust, kind
):
    """Controller ruling: images are opaque; approved and local lanes forward them as-is."""
    gw = gateways(trust)
    resp = send(gw, fmt, build(fmt, "image", carrier(kind), stream))
    assert resp.status_code == 200
    sent = upstream.all_bytes().decode()
    assert image_b64(carrier(kind)) in sent
    assert "[cui-guard:" not in sent


@matrix(("public",))
def test_round_trip_tool_command(gateways, upstream, fmt, stream, trust):
    gw = gateways(trust)
    real = CANARIES["host"]

    def responder(f, path, raw, is_stream):
        ph = re.search(r"host-\d+\.cg\.invalid", raw.decode())
        command = f"ssh {ph.group(0)}" if ph else "ssh NO-PLACEHOLDER"
        return tool_call_response(f, is_stream, command)

    upstream.responder = responder
    resp = send(gw, fmt, build(fmt, "user", f"please log in to {real}", stream))
    assert resp.status_code == 200
    sent = upstream.all_bytes().decode()
    assert real not in sent
    assert PLACEHOLDER_RE.search(sent)
    assert f"ssh {real}" in resp.text, resp.text
    assert not PLACEHOLDER_RE.search(resp.text)


def history(fmt, stream, turns):
    """Conversation `turns` = [(role, text)] in `fmt` shape."""
    if fmt == "openai-responses":
        items = [
            {"role": r, "content": t} if r == "user" else
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": t}]}
            for r, t in turns
        ]  # fmt: skip
        return {"model": "m", "stream": stream, "input": items}
    body = {"model": "m", "stream": stream, "messages": [{"role": r, "content": t} for r, t in turns]}
    if fmt == "anthropic":
        body["max_tokens"] = 64
    return body


def first_turn(fmt, raw):
    data = json.loads(raw)
    items = data["input"] if fmt == "openai-responses" else data["messages"]
    return json.dumps(items[0], sort_keys=True)


@matrix(("public",))
def test_multi_turn_stable_placeholders(gateways, upstream, fmt, stream, trust):
    gw = gateways(trust)
    first = f"hosts {CANARIES['host']} and {CANARIES['ip']} mail {CANARIES['email']} {CANARIES['person']}"
    assert send(gw, fmt, history(fmt, stream, [("user", first)])).status_code == 200
    turn1 = upstream.records[-1].body
    resp2 = send(gw, fmt, history(fmt, stream, [("user", first), ("assistant", "ok"), ("user", "next")]))
    assert resp2.status_code == 200
    turn2 = upstream.records[-1].body
    assert first_turn(fmt, turn1) == first_turn(fmt, turn2)
    for kind in ("host", "ip", "email", "person"):
        assert CANARIES[kind].encode() not in turn1 + turn2


def test_audit_file_contains_no_canaries(gateways, upstream):
    for trust in TRUSTS:
        gw = gateways(trust)
        for fmt in FORMATS:
            for kind in CANARIES:
                send(gw, fmt, build(fmt, "user", carrier(kind), False))
    for trust in TRUSTS:
        path = gateways(trust).dirs.audit_path
        assert path.exists() and path.stat().st_size > 0, trust
        text = path.read_text(encoding="utf-8")
        for kind, needle in CANARIES.items():
            assert needle not in text, f"{kind} canary in the {trust} audit log"
            assert image_b64(needle) not in text
        assert "Plugin ID" not in text and "Plugin Output" not in text
        for line in text.splitlines():
            json.loads(line)  # every record is valid JSON


@pytest.mark.parametrize("fmt", FORMATS)
@pytest.mark.parametrize("trust", TRUSTS)
def test_fail_closed_on_malformed_json(gateways, upstream, fmt, trust):
    gw = gateways(trust)
    for raw in (b"{not json", b"", b"[1, 2]", b'"just a string"', b"{" * 5000, b"\xff\xfe\x00"):
        upstream.reset()
        resp = gw.post(PATHS[fmt], raw)
        assert resp.status_code == 400, raw[:20]
        assert "unparseable" in resp.text, raw[:20]
        assert upstream.records == []


UNKNOWN = {
    "anthropic": lambda: {
        "model": "m", "max_tokens": 8,
        "messages": [{"role": "user", "content": [{"type": "future_block", "x": carrier("host")}]}],
    },
    "openai-responses": lambda: {
        "model": "m", "input": [{"type": "future_item", "x": carrier("host")}],
    },
    "openai-chat": lambda: {
        "model": "m",
        "messages": [{"role": "user", "content": [{"type": "future_part", "x": carrier("host")}]}],
    },
}


@pytest.mark.parametrize("fmt", FORMATS)
@pytest.mark.parametrize("trust", TRUSTS)
def test_fail_closed_on_unknown_block(gateways, upstream, fmt, trust):
    gw = gateways(trust)
    resp = send(gw, fmt, UNKNOWN[fmt]())
    assert resp.status_code == 400
    assert "unparseable" in resp.text
    assert upstream.records == []


def test_fake_upstream_helpers_are_well_formed():
    """Guard the harness itself: scripted replies parse as the formats claim."""
    for fmt in FORMATS:
        ctype, body = text_response(fmt, False)
        assert ctype == "application/json" and json.loads(body)
        ctype, body = text_response(fmt, True)
        assert ctype == "text/event-stream" and b"data:" in body


SIG = "c2lnLXN5bnRoZXRpYw=="  # synthetic signature / encrypted payload


def signed_history(fmt, where, text, stream):
    """History whose model reasoning carries `text`: thinking, redacted_thinking or reasoning summary."""
    if fmt == "anthropic":
        block = (
            {"type": "thinking", "thinking": text, "signature": SIG}
            if where == "thinking"
            else {"type": "redacted_thinking", "data": text}
        )
        return {"model": "m", "max_tokens": 64, "stream": stream, "messages": [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [block, {"type": "text", "text": "done"}]},
            {"role": "user", "content": "continue"},
        ]}  # fmt: skip
    item = {"type": "reasoning", "id": "rs_1", "encrypted_content": SIG,
            "summary": [{"type": "summary_text", "text": text}]}  # fmt: skip
    return {"model": "m", "stream": stream, "input": [
        {"role": "user", "content": "go"}, item,
        {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "done"}]},
        {"role": "user", "content": "continue"},
    ]}  # fmt: skip


SIGNED = [("anthropic", "thinking"), ("anthropic", "redacted_thinking"), ("openai-responses", "reasoning")]


@pytest.mark.parametrize("fmt,where", SIGNED)
@pytest.mark.parametrize("stream", STREAMS)
@pytest.mark.parametrize("kind", list(CANARIES))
def test_no_canary_in_model_reasoning_reaches_public(gateways, upstream, fmt, where, stream, kind):
    """Signed reasoning cannot be rewritten, so any sensitive canary in it blocks the request (I1)."""
    gw = gateways("public")
    resp = send(gw, fmt, signed_history(fmt, where, carrier(kind), stream))
    assert upstream.records == [], f"forwarded: {fmt}/{where}/{kind}"
    assert resp.status_code >= 400
    assert "history.thinking_sensitive" in resp.text
    assert CANARIES[kind] not in resp.text


@pytest.mark.parametrize("fmt,where", SIGNED)
@pytest.mark.parametrize("stream", STREAMS)
def test_clean_model_reasoning_forwarded_byte_identical(gateways, upstream, fmt, where, stream):
    gw = gateways("public")
    body = signed_history(fmt, where, "Plan: read the log, then summarize.", stream)
    resp = send(gw, fmt, body)
    assert resp.status_code == 200
    (rec,) = upstream.records
    sent = json.loads(rec.body)
    if fmt == "anthropic":
        assert sent["messages"][1]["content"][0] == body["messages"][1]["content"][0]
    else:
        assert sent["input"][1] == body["input"][1]
