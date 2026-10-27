"""Egress oracle: no canary in any byte that leaves the gateway, on any path (P1, P2)."""

from __future__ import annotations

import json
import time
from urllib.parse import quote

import httpx
import pytest
from canaries import CANARIES, FORMATS, PATHS, build, carrier
from harness import text_response

# Canaries a public lane masks (forwarded, rewritten), versus those it blocks outright.
BLOCKING = {"cui", "classified", "controlled"}
MASKED = [k for k in CANARIES if k not in BLOCKING]
SCENARIOS = [
    "ok", "upstream_500", "upstream_429", "upstream_timeout", "malformed_sse",
    "client_disconnect", "count_tokens", "blocked", "unparseable",
]  # fmt: skip


def needles() -> list[str]:
    out = []
    for v in CANARIES.values():
        out += [v, quote(v, safe=""), v.lower()]
    return out


def leaked(blob: str) -> list[str]:
    low = blob.lower()
    return [n for n in needles() if n.lower() in low]


def state_text(gw) -> str:
    """Every file under the gateway's state dir (audit log, session file, ...).

    The approved-policy snapshot is skipped: it is the user's own configuration, and holds
    the codenames and names the user asked the guard to protect.
    """
    parts = []
    for p in sorted(gw.dirs.state.rglob("*")):
        if p.is_file() and p.name != "approved-user-policy.json":
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def request_for(fmt: str, kinds, stream: bool) -> dict:
    text = "\n".join(carrier(k) for k in kinds)
    return build(fmt, "user", text, stream)


def run_scenario(gw, upstream, fmt: str, scenario: str) -> None:
    stream = scenario in ("malformed_sse", "client_disconnect")
    if scenario == "upstream_500":
        upstream.status = 500
    elif scenario == "upstream_429":
        upstream.status = 429
    elif scenario == "upstream_timeout":
        def slow(f, path, raw, s):
            time.sleep(1.5)
            return text_response(f, s)

        upstream.responder = slow
    elif scenario == "malformed_sse":
        upstream.responder = lambda f, path, raw, s: (
            "text/event-stream", b"event: x\ndata: {not json\n\ndata: \xff\xfe\n\nevent: message_stop\n")
    elif scenario == "client_disconnect":
        upstream.responder = lambda f, path, raw, s: text_response(f, True, "x" * 50000)

    kinds = list(CANARIES) if scenario == "blocked" else MASKED
    body = request_for(fmt, kinds, stream)
    path = PATHS[fmt]
    if scenario == "count_tokens":
        path = "/v1/messages/count_tokens"
    if scenario == "unparseable":
        raw = ("{not json " + " ".join(CANARIES.values())).encode()
        gw.post(path, raw)
    elif scenario == "upstream_timeout":
        with httpx.Client(trust_env=False, timeout=0.5) as c, pytest.raises(httpx.TimeoutException):
            c.post(gw.base + path, json=body, headers={"x-cui-guard-token": gw.token})
        time.sleep(1.5)  # let the gateway finish with the stalled upstream
    elif scenario == "client_disconnect":
        with httpx.Client(trust_env=False, timeout=30) as c, c.stream(
            "POST", gw.base + path, json=body, headers={"x-cui-guard-token": gw.token}
        ) as r:
            next(r.iter_bytes(), b"")  # read the first bytes, then drop the connection
        time.sleep(0.5)
    else:
        gw.post(path, body)


@pytest.mark.parametrize("fmt", FORMATS)
@pytest.mark.parametrize("scenario", SCENARIOS)
def test_no_canary_in_any_egress_byte(gateways, upstream, fmt, scenario):
    gw = gateways("public")
    run_scenario(gw, upstream, fmt, scenario)
    where = f"{fmt}/{scenario}"
    assert not leaked(upstream.all_bytes().decode("utf-8", "replace")), f"upstream bytes {where}"
    assert not leaked(gw.output()), f"gateway output {where}"
    assert not leaked(gw.dirs.audit_path.read_text(encoding="utf-8")
                      if gw.dirs.audit_path.exists() else ""), f"audit {where}"  # fmt: skip
    assert not leaked(state_text(gw)), f"state dir {where}"


@pytest.mark.parametrize("fmt", FORMATS)
@pytest.mark.parametrize("kind", ["host", "ip", "email", "secret_aws", "cui"])
def test_query_string_canary_not_forwarded(gateways, upstream, fmt, kind):
    gw = gateways("public")
    body = build(fmt, "user", "hello", False)
    gw.post(PATHS[fmt] + "?q=" + quote(CANARIES[kind], safe=""), body)
    assert not leaked(upstream.all_bytes().decode("utf-8", "replace"))
    assert not leaked(state_text(gw))


@pytest.mark.parametrize("fmt", FORMATS)
def test_benign_query_string_still_forwarded(gateways, upstream, fmt):
    gw = gateways("public")
    resp = gw.post(PATHS[fmt] + "?beta=true", build(fmt, "user", "hello", False))
    assert resp.status_code == 200
    assert upstream.records[0].query == "beta=true"


@pytest.mark.parametrize("fmt", FORMATS)
def test_only_configured_upstream_is_contacted(gateways, upstream, fmt):
    gw = gateways("public")
    resp = gw.post(PATHS[fmt], build(fmt, "user", "hello", False))
    assert resp.status_code == 200
    log = [e for e in gw.egress_log() if e["op"] == "connect"]
    assert log, "the hook recorded no connects"
    assert {e["host"] for e in log} <= {"127.0.0.1"}
    # The gateway's own listener is accepted, not connected; only the upstream is dialled.
    assert {e["port"] for e in log} <= {upstream.port}


def test_no_dns_lookups_beyond_upstream(gateways, upstream):
    gw = gateways("public")
    gw.post(PATHS["anthropic"], build("anthropic", "user", "hello", False))
    lookups = [e for e in gw.egress_log() if e["op"] == "getaddrinfo"]
    assert {e["host"] for e in lookups} <= {"127.0.0.1", "localhost"}


def test_tracebacks_carry_no_canary(gateways, upstream):
    gw = gateways("public")
    c = CANARIES["secret_anthropic"]
    crafted = [
        {"messages": [{"role": 7, "content": [{"type": 123, "text": c}]}], "system": {"x": c}},
        {"messages": [c], "system": [c, None, {"type": "text", "text": {"nested": c}}]},
        {"input": [{"type": c, "content": c}], "messages": {"role": c}, "model": [c]},
        {"messages": [{"role": "user", "content": [{"type": "tool_use", "input": c, "id": c}]}]},
    ]
    for fmt in FORMATS:
        for body in crafted:
            gw.post(PATHS[fmt], json.dumps(body).encode())
    gw.post(PATHS["anthropic"], b"[" * 50000 + c.encode())  # recursion bait
    assert not leaked(gw.output())
    assert not leaked(upstream.all_bytes().decode("utf-8", "replace"))
    assert not leaked(state_text(gw))
