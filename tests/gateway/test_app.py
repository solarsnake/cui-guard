import asyncio
import json

import httpx

from cui_guard.adapters.sse import SSEDecoder, SSEEvent, encode_event
from cui_guard.gateway import app as gw
from cui_guard.gateway.app import GatewayConfig, create_app
from cui_guard.model import Trust
from cui_guard.policy.loader import load_builtin_layer
from cui_guard.policy.merge import merge_layers
from cui_guard.policy.schema import AuditConfig, Endpoint
from cui_guard.pseudo.mapper import PLACEHOLDER_RE

TOKEN = "tok-123"
HOST = "db.example.mil"
KEY = "sk-" + "ant-" + "A" * 24
CUI = "CUI//SP-CTI"


def make_cfg(tmp_path, mode="gateway", formats=("anthropic",), cred="up-key"):
    policy = merge_layers(load_builtin_layer(), None, None)
    policy.audit = AuditConfig(path=str(tmp_path / "audit.jsonl"))
    lane = Endpoint("public", "https://llm.example.invalid", formats, Trust.PUBLIC, "env:X")
    return GatewayConfig(TOKEN, "claude", lane, policy, mode, cred, False, "sess")


class Upstream:
    def __init__(self, handler=None):
        self.requests: list[httpx.Request] = []
        self.handler = handler or self.echo

    def echo(self, req):
        body = json.loads(req.content)
        text = body["messages"][0]["content"]
        return httpx.Response(200, json={"type": "message", "content": [{"type": "text", "text": text}]})

    def __call__(self, req):
        self.requests.append(req)
        return self.handler(req)

    @property
    def bodies(self):
        return [r.content.decode() for r in self.requests]


def client(cfg, up, **kw):
    app = create_app(cfg, transport=httpx.MockTransport(up), **kw)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw")


def msg(text, **extra):
    return {"model": "m", "max_tokens": 5, "messages": [{"role": "user", "content": text}], **extra}


H = {"x-cui-guard-token": TOKEN}


def audit_rows(tmp_path):
    p = tmp_path / "audit.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


async def test_missing_token_401(tmp_path):
    up = Upstream()
    async with client(make_cfg(tmp_path), up) as c:
        r = await c.post("/v1/messages", json=msg("hi"))
        assert r.status_code == 401
        r = await c.post("/v1/messages", json=msg("hi"), headers={"x-cui-guard-token": "bad"})
        assert r.status_code == 401
    assert up.requests == []


async def test_bearer_token_in_gateway_mode(tmp_path):
    up = Upstream()
    async with client(make_cfg(tmp_path), up) as c:
        r = await c.post("/v1/messages", json=msg("hi"), headers={"authorization": f"Bearer {TOKEN}"})
        assert r.status_code == 200
    assert "authorization" not in up.requests[0].headers


async def test_upstream_never_sees_canaries(tmp_path):
    up = Upstream()
    body = {
        "model": "m", "max_tokens": 5,
        "messages": [
            {"role": "user", "content": f"connect to {HOST}"},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": f"key {KEY}"}]},
        ],
    }  # fmt: skip
    async with client(make_cfg(tmp_path), up) as c:
        r = await c.post("/v1/messages?beta=true", json=body, headers=H)
    assert r.status_code == 200
    assert len(up.requests) == 1
    assert HOST not in up.bodies[0] and KEY not in up.bodies[0]
    assert str(up.requests[0].url) == "https://llm.example.invalid/v1/messages?beta=true"


async def test_blocked_request_not_forwarded(tmp_path):
    up = Upstream()
    async with client(make_cfg(tmp_path), up) as c:
        r = await c.post("/v1/messages", json=msg(f"here {CUI} data"), headers=H)
        bad = await c.post("/v1/messages", content=b"[1,2]", headers=H)
    assert r.status_code == 400 and up.requests == []
    m = r.json()["error"]["message"]
    assert m.startswith("cui-guard blocked this request: ") and "No override available." in m
    assert CUI not in m  # excerpt is masked
    assert bad.status_code == 400 and "unparseable" in bad.json()["error"]["message"]


async def test_gateway_mode_swaps_credential(tmp_path):
    up = Upstream()
    hdr = {**H, "x-api-key": "agent-key", "authorization": "Bearer agent-oauth"}
    async with client(make_cfg(tmp_path), up) as c:
        await c.post("/v1/messages", json=msg("hi"), headers=hdr)
    h = up.requests[0].headers
    assert h["x-api-key"] == "up-key" and "authorization" not in h


async def test_none_mode_sends_no_credential(tmp_path):
    up = Upstream()
    hdr = {**H, "x-api-key": "agent-key", "authorization": "Bearer agent-oauth"}
    async with client(make_cfg(tmp_path, mode="none", cred=None), up) as c:
        await c.post("/v1/messages", json=msg("hi"), headers=hdr)
    h = up.requests[0].headers
    assert "x-api-key" not in h and "authorization" not in h


async def test_passthrough_mode_forwards_oauth_and_beta(tmp_path):
    up = Upstream()
    hdr = {**H, "authorization": "Bearer agent-oauth", "anthropic-beta": "oauth-2025", "anthropic-version": "2023-06-01"}
    async with client(make_cfg(tmp_path, mode="passthrough"), up) as c:
        await c.post("/v1/messages", json=msg("hi"), headers=hdr)
    h = up.requests[0].headers
    assert h["authorization"] == "Bearer agent-oauth"
    assert h["anthropic-beta"] == "oauth-2025" and h["anthropic-version"] == "2023-06-01"
    assert "x-api-key" not in h


async def test_guard_header_stripped(tmp_path):
    up = Upstream()
    async with client(make_cfg(tmp_path), up) as c:
        await c.post("/v1/messages", json=msg("hi"), headers={**H, "x-custom": "yes"})
    h = up.requests[0].headers
    assert "x-cui-guard-token" not in h and h["x-custom"] == "yes"


async def test_count_tokens_404_and_hello(tmp_path):
    up = Upstream()
    async with client(make_cfg(tmp_path), up) as c:
        r = await c.post("/v1/messages/count_tokens", json=msg("hi"), headers=H)
        assert r.status_code == 404
        assert (await c.head("/api/hello", headers=H)).status_code == 200
    assert up.requests == []


def sse_bytes(events):
    return b"".join(encode_event(SSEEvent(e["type"], json.dumps(e))) for e in events)


def stream_events(text_parts):
    ev = [
        {"type": "message_start", "message": {"id": "m", "type": "message", "role": "assistant", "content": []}},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    ]
    for t in text_parts:
        ev.append({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": t}})
    return ev


def stream_handler(parts_fn, fail_after=None):
    def handler(req):
        ph = PLACEHOLDER_RE.search(req.content.decode()).group(0)
        evs = stream_events(parts_fn(ph))
        tail = [
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": "end_turn"}},
            {"type": "message_stop"},
        ]

        async def body():
            for i, e in enumerate(evs + tail):
                if fail_after is not None and i == fail_after:
                    raise httpx.ReadError("boom")
                yield sse_bytes([e])
                await asyncio.sleep(0)

        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=body())

    return handler


def parse_sse(content):
    return SSEDecoder().feed(content) + SSEDecoder().close()


async def test_stream_rehydrated_end_to_end(tmp_path):
    def parts(ph):
        return ["the host ", ph[:4], ph[4:9], ph[9:], " is up"]

    up = Upstream(stream_handler(parts))
    async with client(make_cfg(tmp_path), up) as c:
        r = await c.post("/v1/messages", json=msg(f"ping {HOST}", stream=True), headers=H)
    assert r.status_code == 200
    evs = parse_sse(r.content)
    text = "".join(
        json.loads(e.data)["delta"]["text"] for e in evs if e.event == "content_block_delta"
    )
    assert text == f"the host {HOST} is up"
    assert HOST not in up.bodies[0]
    assert audit_rows(tmp_path)[0]["action"] == "forwarded"


async def test_upstream_error_passthrough(tmp_path):
    err = {"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}}
    up = Upstream(lambda req: httpx.Response(429, json=err))
    async with client(make_cfg(tmp_path), up) as c:
        r = await c.post("/v1/messages", json=msg("hi"), headers=H)
        s = await c.post("/v1/messages", json=msg("hi", stream=True), headers=H)
    assert r.status_code == 429 and r.json() == err
    assert s.status_code == 429 and s.json() == err


async def test_upstream_error_mid_stream(tmp_path):
    up = Upstream(stream_handler(lambda ph: ["found ", ph, " and more"], fail_after=4))
    async with client(make_cfg(tmp_path), up) as c:
        r = await c.post("/v1/messages", json=msg(f"ping {HOST}", stream=True), headers=H)
    evs = parse_sse(r.content)
    assert [e.event for e in evs].count("error") == 1 and evs[-1].event == "error"
    text = "".join(
        json.loads(e.data)["delta"]["text"] for e in evs if e.event == "content_block_delta"
    )
    assert text == f"found {HOST}"
    assert PLACEHOLDER_RE.search(r.content.decode()) is None
    assert json.loads(evs[-1].data)["error"]["message"] == "upstream stream interrupted"


async def test_ping_while_holding_back(tmp_path, monkeypatch):
    monkeypatch.setattr(gw, "PING_INTERVAL_S", 0.05)

    def handler(req):
        async def body():
            for e in stream_events(["hello"]):
                yield sse_bytes([e])
            await asyncio.sleep(0.3)
            for e in [{"type": "content_block_stop", "index": 0}, {"type": "message_stop"}]:
                yield sse_bytes([e])

        return httpx.Response(200, content=body())

    async with client(make_cfg(tmp_path), Upstream(handler)) as c:
        r = await c.post("/v1/messages", json=msg("hi", stream=True), headers=H)
    assert "ping" in [e.event for e in parse_sse(r.content)]


async def test_one_audit_record_per_request(tmp_path):
    up = Upstream()
    async with client(make_cfg(tmp_path), up) as c:
        await c.post("/v1/messages", json=msg("hi"), headers=H)
        await c.post("/v1/messages", json=msg(f"{CUI} x"), headers=H)
        await c.post("/v1/messages", json=msg(f"to {HOST}", stream=True), headers=H)
    rows = audit_rows(tmp_path)
    assert [r["action"] for r in rows] == ["forwarded", "blocked", "forwarded"]
    text = (tmp_path / "audit.jsonl").read_text()
    assert HOST not in text and CUI not in text
    assert rows[0]["agent"] == "claude" and rows[0]["lane"] == "public"


async def test_leftover_count_audited(tmp_path):
    def echo_unknown(req):
        return httpx.Response(200, json={"type": "message", "content": [{"type": "text", "text": "see CG_PERSON_99"}]})

    async with client(make_cfg(tmp_path), Upstream(echo_unknown)) as c:
        r = await c.post("/v1/messages", json=msg("hi"), headers=H)
    assert "CG_PERSON_99" in r.text
    assert audit_rows(tmp_path)[0]["leftover_count"] == 1


async def test_format_mismatch_400(tmp_path):
    up = Upstream()
    async with client(make_cfg(tmp_path, formats=("openai-chat",)), up) as c:
        r = await c.post("/v1/messages", json=msg("hi"), headers=H)
    assert r.status_code == 400 and "anthropic" in r.json()["error"]["message"]
    assert up.requests == []


def test_config_json_roundtrip(tmp_path):
    cfg = make_cfg(tmp_path)
    again = GatewayConfig.from_json(cfg.to_json())
    assert again.lane == cfg.lane and again.policy.to_dict() == cfg.policy.to_dict()
    assert again.token == TOKEN and again.credential_mode == "gateway"
