"""The HTTP gateway: authenticate, scan, forward, rehydrate, audit. Fails closed."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from cui_guard.adapters.anthropic import AnthropicAdapter
from cui_guard.adapters.base import Adapter
from cui_guard.adapters.sse import SSEDecoder, SSEEvent, encode_event
from cui_guard.audit import AuditLog, AuditUnavailable, sha256_json
from cui_guard.detect.engine import Detector
from cui_guard.detect.ner import load_presidio
from cui_guard.detect.rules import load_builtin_rules
from cui_guard.model import Action, DetClass, Trust
from cui_guard.override.store import OverrideStore
from cui_guard.pipeline import BlockInfo, Decision, Pipeline
from cui_guard.policy.schema import EffectivePolicy, Endpoint
from cui_guard.pseudo.mapper import SessionMap

if TYPE_CHECKING:
    from cui_guard.override.human import HumanChannel

GUARD_HEADER = "x-cui-guard-token"
PING_INTERVAL_S = 15.0
_HOP_BY_HOP = frozenset(
    {
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
    }
)  # fmt: skip
_DROP_RESPONSE = _HOP_BY_HOP | {"content-encoding"}
_LEFTOVER_NOTE = re.compile(r"leftover_placeholders=(\d+)")
_PING = SSEEvent("ping", json.dumps({"type": "ping"}))


@dataclass
class GatewayConfig:
    token: str
    agent: str
    lane: Endpoint
    policy: EffectivePolicy
    credential_mode: Literal["gateway", "passthrough", "none"]
    upstream_credential: str | None
    headless: bool
    session_id: str

    def to_json(self) -> str:
        lane = self.lane
        return json.dumps(
            {
                "token": self.token,
                "agent": self.agent,
                "lane": {
                    "name": lane.name,
                    "url": lane.url,
                    "formats": list(lane.formats),
                    "trust": lane.trust.value,
                    "credential": lane.credential,
                },
                "policy": self.policy.to_dict(),
                "credential_mode": self.credential_mode,
                "upstream_credential": self.upstream_credential,
                "headless": self.headless,
                "session_id": self.session_id,
            }
        )

    @classmethod
    def from_json(cls, text: str) -> GatewayConfig:
        d = json.loads(text)
        ln = d["lane"]
        lane = Endpoint(
            name=ln["name"],
            url=ln["url"],
            formats=tuple(ln["formats"]),
            trust=Trust(ln["trust"]),
            credential=ln["credential"],
        )
        mode = d["credential_mode"]
        if mode not in ("gateway", "passthrough", "none"):
            raise ValueError(f"unknown credential_mode: {mode!r}")
        return cls(
            token=d["token"],
            agent=d["agent"],
            lane=lane,
            policy=EffectivePolicy.from_dict(d["policy"]),
            credential_mode=mode,
            upstream_credential=d.get("upstream_credential"),
            headless=bool(d["headless"]),
            session_id=d["session_id"],
        )


def _fail_block(rule_id: str, location: str, why: str) -> Decision:
    digest = hashlib.sha256(rule_id.encode()).hexdigest()
    block = BlockInfo(rule_id, DetClass.UNPARSEABLE, Action.BLOCK_HARD, location, why, digest, None)
    return Decision(blocked=[block], hit_counts={rule_id: 1})


def _block_message(decision: Decision, offered: bool) -> str:
    parts = [
        f"{b.rule_id} [{b.cls.value}] at {b.location}: {b.excerpt}" for b in decision.blocked
    ]
    ids = [b.override_id for b in decision.blocked if b.override_id]
    msg = "cui-guard blocked this request: " + "; ".join(parts) + ". "
    if offered and ids:
        msg += f"Override offered on your screen (ID {ids[0]})."
    else:
        msg += "No override available."
    return msg


def _has_pending(rewriter: Any) -> bool:
    """True while the rewriter holds an open block that may be holding text back."""
    return bool(getattr(rewriter, "_text", None) or getattr(rewriter, "_args", None))


def _leftover_from_notes(notes: list[str]) -> int:
    total = 0
    for n in notes:
        m = _LEFTOVER_NOTE.fullmatch(n)
        if m:
            total += int(m.group(1))
    return total


def create_app(
    cfg: GatewayConfig,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    channel: HumanChannel | None = None,
) -> Starlette:
    policy = cfg.policy
    lane = cfg.lane
    adapters: dict[str, Adapter] = {a.format: a for a in (AnthropicAdapter(),)}
    smap = SessionMap()
    overrides = OverrideStore()
    detector = Detector(load_builtin_rules() + policy.extra_rules, policy.identifiers, load_presidio())
    pipeline = Pipeline(policy, detector, smap, lane.trust, overrides)
    audit = AuditLog(policy.audit, cfg.session_id, sha256_json(policy.to_dict()))
    client = httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(connect=10, read=None, write=60, pool=10),
    )
    base_url = lane.url.rstrip("/")
    tasks: set[asyncio.Task] = set()
    state = {"leftover_notified": False}

    def notify(fn, *args) -> None:
        if channel is None:
            return

        async def run() -> None:
            # a notification failure never affects the request
            with contextlib.suppress(Exception):
                await asyncio.get_running_loop().run_in_executor(None, fn, *args)

        t = asyncio.ensure_future(run())
        tasks.add(t)
        t.add_done_callback(tasks.discard)

    def notify_leftover(count: int) -> None:
        if channel is None or count <= 0 or state["leftover_notified"]:
            return
        state["leftover_notified"] = True
        info = BlockInfo(
            "placeholder.leftover", DetClass.CONTROLLED_CONTENT, Action.ALLOW, "response",
            f"{count} unresolved placeholder(s) in a model response", "", None,
        )  # fmt: skip
        notify(channel.notify_block, info, False)

    def authorized(request: Request) -> bool:
        got = request.headers.get(GUARD_HEADER)
        if got is not None and hmac.compare_digest(got.encode(), cfg.token.encode()):
            return True
        if cfg.credential_mode in ("gateway", "none"):
            auth = request.headers.get("authorization", "")
            scheme, _, value = auth.partition(" ")
            if scheme.lower() == "bearer" and hmac.compare_digest(
                value.strip().encode(), cfg.token.encode()
            ):
                return True
        return False

    def upstream_headers(request: Request, adapter: Adapter) -> list[tuple[str, str]]:
        drop = set(_HOP_BY_HOP) | {GUARD_HEADER, "accept-encoding"}
        if cfg.credential_mode != "passthrough":
            drop |= {"authorization", "x-api-key"}
        out = [(k, v) for k, v in request.headers.items() if k.lower() not in drop]
        if cfg.credential_mode == "gateway" and cfg.upstream_credential:
            if adapter.format == "anthropic":
                out.append(("x-api-key", cfg.upstream_credential))
            else:
                out.append(("authorization", f"Bearer {cfg.upstream_credential}"))
        return out

    def response_headers(resp: httpx.Response) -> dict[str, str]:
        return {k: v for k, v in resp.headers.items() if k.lower() not in _DROP_RESPONSE}

    def record(decision: Decision, request_hash: str, leftover: int = 0) -> None:
        offered = [
            {"id": b.override_id, "rule_id": b.rule_id, "status": "offered"}
            for b in decision.blocked
            if b.override_id and channel is not None and not cfg.headless
        ]
        audit.record(
            agent=cfg.agent, lane=lane.name, trust=lane.trust, decision=decision,
            request_hash=request_hash, overrides=offered or None, leftover_count=leftover,
        )  # fmt: skip

    def blocked_response(adapter: Adapter, decision: Decision, request_hash: str) -> Response:
        offered = channel is not None and not cfg.headless
        msg = _block_message(decision, offered)
        try:
            record(decision, request_hash)
        except AuditUnavailable:
            msg = "cui-guard blocked this request: audit log unavailable."
        if channel is not None:
            for b in decision.blocked:
                notify(channel.notify_block, b, offered and b.override_id is not None)
        return JSONResponse(adapter.error_body(msg), status_code=adapter.block_status)

    async def hello(request: Request) -> Response:
        if not authorized(request):
            return Response(status_code=401)
        return Response(status_code=200)

    async def count_tokens(request: Request) -> Response:
        if not authorized(request):
            return Response(status_code=401)
        return JSONResponse(
            {"type": "error", "error": {"type": "not_found_error", "message": "not supported"}},
            status_code=404,
        )

    def make_handler(adapter: Adapter):
        async def handle(request: Request) -> Response:
            if not authorized(request):
                return JSONResponse(
                    adapter.error_body("cui-guard: missing or invalid session token"),
                    status_code=401,
                )
            if adapter.format not in lane.formats:
                return JSONResponse(
                    adapter.error_body(
                        f"cui-guard: lane {lane.name!r} does not accept the {adapter.format!r} format"
                    ),
                    status_code=400,
                )
            raw = await request.body()
            request_hash = hashlib.sha256(raw).hexdigest()
            try:
                body = json.loads(raw)
            except (ValueError, RecursionError):
                body = None
            if not isinstance(body, dict):
                decision = _fail_block("unparseable", "request", "request body is not a JSON object")
                return blocked_response(adapter, decision, request_hash)
            try:
                view = adapter.extract(body)
                decision = await asyncio.to_thread(pipeline.evaluate, view)
                if decision.forward:
                    out_bytes = json.dumps(
                        adapter.apply(body, decision), ensure_ascii=False
                    ).encode("utf-8")
            except Exception as e:  # noqa: BLE001 - fail closed
                decision = _fail_block("internal.error", "request", type(e).__name__)
            if not decision.forward:
                return blocked_response(adapter, decision, request_hash)
            try:
                audit.preflight()
            except AuditUnavailable:
                return JSONResponse(
                    adapter.error_body("cui-guard blocked this request: audit log unavailable."),
                    status_code=adapter.block_status,
                )
            url = base_url + request.url.path
            if request.url.query:
                url += "?" + request.url.query
            headers = upstream_headers(request, adapter)
            headers = [(k, v) for k, v in headers if k.lower() != "content-type"]
            headers.append(("content-type", "application/json"))
            req = client.build_request("POST", url, headers=headers, content=out_bytes)
            if body.get("stream") is True:
                return await stream_path(adapter, req, decision, request_hash)
            return await plain_path(adapter, req, decision, request_hash)

        return handle

    async def send_upstream(adapter: Adapter, req: httpx.Request, stream: bool):
        try:
            return await client.send(req, stream=stream), None
        except Exception:  # noqa: BLE001
            return None, JSONResponse(
                adapter.error_body("cui-guard: upstream request failed"), status_code=502
            )

    async def plain_path(adapter, req, decision, request_hash) -> Response:
        resp, err = await send_upstream(adapter, req, False)
        leftover = 0
        if err is not None:
            result: Response = err
        elif resp.status_code >= 400:
            result = Response(resp.content, resp.status_code, response_headers(resp))
        else:
            try:
                data = json.loads(resp.content)
                if not isinstance(data, dict):
                    raise TypeError
                new = adapter.rehydrate_response(data, smap)
                leftover = len(smap.leftover_placeholders(json.dumps(new, ensure_ascii=False)))
                result = Response(
                    json.dumps(new, ensure_ascii=False).encode("utf-8"),
                    resp.status_code,
                    {**response_headers(resp), "content-type": "application/json"},
                )
            except Exception:  # noqa: BLE001 - fail closed on an unreadable response
                result = JSONResponse(
                    adapter.error_body("cui-guard: unreadable upstream response"), status_code=502
                )
        try:
            record(decision, request_hash, leftover)
        except AuditUnavailable:
            return JSONResponse(
                adapter.error_body("cui-guard blocked this response: audit log unavailable."),
                status_code=adapter.block_status,
            )
        notify_leftover(leftover)
        return result

    async def stream_path(adapter, req, decision, request_hash) -> Response:
        resp, err = await send_upstream(adapter, req, True)
        if err is not None:
            try:
                record(decision, request_hash)
            except AuditUnavailable:
                pass
            return err
        if resp.status_code >= 400:
            content = await resp.aread()
            await resp.aclose()
            try:
                record(decision, request_hash)
            except AuditUnavailable:
                pass
            return Response(content, resp.status_code, response_headers(resp))

        async def gen() -> AsyncIterator[bytes]:
            rewriter = adapter.stream_rewriter(smap)
            decoder = SSEDecoder()
            it = resp.aiter_bytes().__aiter__()
            nxt: asyncio.Future | None = None
            try:
                try:
                    while True:
                        nxt = asyncio.ensure_future(it.__anext__())
                        while True:
                            done, _ = await asyncio.wait({nxt}, timeout=PING_INTERVAL_S)
                            if done:
                                break
                            if _has_pending(rewriter):
                                yield encode_event(_PING)
                        try:
                            chunk = nxt.result()
                        except StopAsyncIteration:
                            nxt = None
                            break
                        nxt = None
                        for ev in decoder.feed(chunk):
                            for out in rewriter.feed(ev):
                                yield encode_event(out)
                    for ev in decoder.close():
                        for out in rewriter.feed(ev):
                            yield encode_event(out)
                    for out in rewriter.finish():
                        yield encode_event(out)
                except Exception:  # noqa: BLE001 - interrupted or unrewritable: close out safely
                    with contextlib.suppress(Exception):
                        for out in rewriter.finish():
                            yield encode_event(out)
                    err_ev = SSEEvent(
                        "error",
                        json.dumps(adapter.error_body("upstream stream interrupted")),
                    )
                    yield encode_event(err_ev)
            finally:
                if nxt is not None:
                    nxt.cancel()
                await resp.aclose()
                leftover = _leftover_from_notes(rewriter.notes)
                try:
                    record(decision, request_hash, leftover)
                except AuditUnavailable:
                    pass
                notify_leftover(leftover)

        headers = response_headers(resp)
        headers["content-type"] = "text/event-stream"
        headers["cache-control"] = "no-cache"
        return StreamingResponse(gen(), status_code=resp.status_code, headers=headers)

    @asynccontextmanager
    async def lifespan(app: Starlette):
        yield
        await client.aclose()

    routes: list[Route] = [
        Route("/api/hello", hello, methods=["HEAD"]),
        Route("/v1/messages/count_tokens", count_tokens, methods=["POST"]),
    ]
    for adapter in adapters.values():
        for path in adapter.paths:
            routes.append(Route(path, make_handler(adapter), methods=["POST"]))
    return Starlette(routes=routes, lifespan=lifespan)
