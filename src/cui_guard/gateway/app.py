"""The HTTP gateway: authenticate, scan, forward, rehydrate, audit. Fails closed."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import re
import sys
import threading
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal
from urllib.parse import unquote_plus, urlparse

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from cui_guard.adapters.anthropic import AnthropicAdapter
from cui_guard.adapters.base import Adapter
from cui_guard.adapters.openai_chat import OpenAIChatAdapter
from cui_guard.adapters.openai_responses import OpenAIResponsesAdapter
from cui_guard.adapters.sse import SSEDecoder, SSEEvent, encode_event
from cui_guard.audit import AuditLog, AuditUnavailable, sha256_json
from cui_guard.detect.engine import Detector
from cui_guard.detect.ner import load_presidio
from cui_guard.detect.rules import load_builtin_rules
from cui_guard.fips import upstream_ssl_context
from cui_guard.model import Action, DetClass, Trust
from cui_guard.override.human import load_messages, render, warning_key
from cui_guard.override.store import OverrideStore
from cui_guard.pipeline import BlockInfo, Decision, Pipeline, Segment
from cui_guard.policy.schema import EffectivePolicy, Endpoint, is_loopback_host
from cui_guard.pseudo.egress import EgressGuard
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
PROMPT_COOLDOWN_S = 60.0
MAX_UNGRANTED_FLOWS = 3
_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})
MAX_BODY_BYTES = 32 * 1024 * 1024
_TOO_LARGE = "cui-guard: request body exceeds 32 MiB"
_CROSS_SITE = frozenset({"cross-site", "same-site"})


def _allowed_hosts(port: int) -> frozenset[str]:
    return frozenset({f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"})


class LoopbackGuard:
    """Pure-ASGI guard, ahead of routing and any body read: refuses DNS-rebinding Host
    values and browser-originated requests (Origin, cross-site Sec-Fetch-Site)."""

    def __init__(self, app) -> None:
        self.app = app

    def _reason(self, scope, port: int) -> str | None:
        hosts: list[str] = []
        origin = False
        site = ""
        names = [k for k, _ in scope["headers"]]
        if b"content-length" in names and b"transfer-encoding" in names:
            return "conflicting Content-Length and Transfer-Encoding"
        for k, v in scope["headers"]:
            if k == b"host":
                hosts.append(v.decode("latin-1").lower())
            elif k == b"origin":
                origin = True
            elif k == b"sec-fetch-site":
                site = v.decode("latin-1").strip().lower()
        allowed = _allowed_hosts(port)
        if not hosts or any(h not in allowed for h in hosts):
            return "host not allowed"
        if origin:
            return "browser-originated request refused (Origin header)"
        if site in _CROSS_SITE:
            return "browser-originated request refused (cross-site fetch)"
        return None

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            # The port is the one the server actually listens on (scope["server"]); with no
            # loopback address and port to check against, fail closed.
            server = scope.get("server")
            if server and server[0] in _LOOPBACK and server[1]:
                reason = self._reason(scope, server[1])
            else:
                reason = "not served on a loopback address"
            if reason is not None:
                smuggling = reason.startswith("conflicting")
                body = {
                    "type": "error",
                    "error": {"type": "bad_request" if smuggling else "forbidden", "message": f"cui-guard: {reason}"},
                }
                await JSONResponse(body, status_code=400 if smuggling else 403)(scope, receive, send)
                return
        await self.app(scope, receive, send)


class BodyTooLarge(Exception):
    pass


async def read_capped(request: Request) -> bytes:
    """Read the body, refusing as soon as it is known or seen to exceed MAX_BODY_BYTES."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise BodyTooLarge
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            raise BodyTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


@dataclass
class GatewayConfig:
    token: str = field(repr=False)
    agent: str
    lane: Endpoint
    policy: EffectivePolicy
    credential_mode: Literal["gateway", "passthrough", "none"]
    upstream_credential: str | None = field(repr=False)
    headless: bool
    session_id: str

    def __post_init__(self) -> None:
        if not self.token:
            raise ValueError("gateway token must not be empty")
        if self.credential_mode == "gateway" and not self.upstream_credential:
            raise ValueError("credential_mode 'gateway' requires an upstream_credential")

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
                    "ca_file": lane.ca_file,
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
            ca_file=ln["ca_file"],
        )
        if lane.ca_file is not None and not isinstance(lane.ca_file, str):
            raise ValueError("lane ca_file must be a string or null")
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


def _block_message(
    decision: Decision, offered: bool, messages: dict[str, str], poc: str | None
) -> str:
    parts = [
        f"{b.rule_id} [{b.cls.value}] at {b.location}: {b.excerpt}" for b in decision.blocked
    ]
    ids = [b.override_id for b in decision.blocked if b.override_id]
    msg = "cui-guard blocked this request: " + "; ".join(parts) + ". "
    if any(b.cls == DetClass.CLASSIFIED_MARKING for b in decision.blocked):
        msg += " ".join(render(messages["stop.classified"], poc).split())
    elif offered and ids:
        msg += f"Override offered on your screen (ID {', '.join(dict.fromkeys(ids))})."
    else:
        msg += " ".join(render(messages["blocked.no_override"], poc).split())
    return msg


def _leftover_from_notes(notes: list[str]) -> int:
    total = 0
    for n in notes:
        m = _LEFTOVER_NOTE.fullmatch(n)
        if m:
            total += int(m.group(1))
    return total


def _withheld_decision(count: int) -> Decision:
    """Audit record for tool-call strings left unrehydrated (H4): the count only."""
    return Decision(hit_counts={"rehydrate.withheld": count})


def create_app(
    cfg: GatewayConfig,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    channel: HumanChannel | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> Starlette:
    policy = cfg.policy
    lane = cfg.lane
    adapters: dict[str, Adapter] = {
        a.format: a for a in (AnthropicAdapter(), OpenAIResponsesAdapter(), OpenAIChatAdapter())
    }
    egress = EgressGuard(policy.identifiers, policy.egress_rehydration)  # type: ignore[arg-type]
    smap = SessionMap(egress=egress)
    overrides = OverrideStore()
    messages = load_messages(policy.messages_file)  # an unreadable org file fails startup
    detector = Detector(load_builtin_rules() + policy.extra_rules, policy.identifiers, load_presidio())
    pipeline = Pipeline(policy, detector, smap, lane.trust, overrides)
    audit = AuditLog(policy.audit, cfg.session_id, sha256_json(policy.to_dict()))
    host = (urlparse(lane.url).hostname or "").lower()
    client = httpx.AsyncClient(
        transport=transport,
        # TLS 1.2 floor and verification for every upstream; ca_file replaces the trust store.
        verify=upstream_ssl_context(lane.ca_file, policy.fips == "require"),
        trust_env=not is_loopback_host(host),  # never route loopback traffic through a proxy
        # read is seconds of inactivity, not a total: a hung upstream fails after 10 minutes.
        timeout=httpx.Timeout(connect=10, read=600, write=60, pool=10),
    )
    base_url = lane.url.rstrip("/")
    tasks: set[asyncio.Task] = set()
    state = {"leftover_notified": False}
    in_flight: set[str] = set()
    in_flight_lock = threading.Lock()
    ungranted: dict[str, int] = {}  # flows per override id that ended without a grant
    last_ended: dict[str, float] = {}

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

    def run_override_flow(block: BlockInfo) -> None:
        """Human flow for one override ID, on its own thread: notify, justify, authenticate, grant."""
        assert channel is not None and block.override_id is not None  # noqa: S101 -- type narrowing only; both are set before this thread starts
        oid = block.override_id
        granted = False
        try:
            channel.notify_block(block, True)
            warning = render(messages[warning_key(block)], policy.poc)
            justification = channel.request_justification(block, warning)
            if not justification or not justification.strip():
                return
            if not channel.authenticate(f"cui-guard override {oid}: {block.rule_id}"):
                return
            entry = {
                "id": oid, "rule_id": block.rule_id, "content_hash": block.content_hash,
                "justification": justification, "status": "granted",
            }  # fmt: skip
            # audit first: if the record cannot be written, nothing is granted
            audit.record(
                agent=cfg.agent, lane=lane.name, trust=lane.trust,
                decision=Decision(hit_counts={block.rule_id: 1}),
                request_hash=block.content_hash, overrides=[entry], action="override",
            )  # fmt: skip
            overrides.grant(oid, justification)
            granted = True
        except Exception:  # noqa: BLE001, S110 - any failure means no override
            pass
        finally:
            suppress_now = False
            with in_flight_lock:
                in_flight.discard(oid)
                if not granted:
                    ungranted[oid] = ungranted.get(oid, 0) + 1
                    last_ended[oid] = clock()
                    suppress_now = ungranted[oid] == MAX_UNGRANTED_FLOWS
            if suppress_now:
                with contextlib.suppress(Exception):
                    channel.notify_block(block, False)  # the block stands; no more prompts

    def start_override_flow(block: BlockInfo) -> None:
        oid = block.override_id
        if channel is None or oid is None:
            return
        with in_flight_lock:
            if oid in in_flight:
                return  # a dialog for this content is already open
            if ungranted.get(oid, 0) >= MAX_UNGRANTED_FLOWS:
                return  # prompt fatigue: the block stands for this session
            ended = last_ended.get(oid)
            if ended is not None and clock() - ended < PROMPT_COOLDOWN_S:
                return
            in_flight.add(oid)
        try:
            threading.Thread(target=run_override_flow, args=(block,), daemon=True).start()
        except Exception:  # noqa: BLE001
            with in_flight_lock:
                in_flight.discard(oid)

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

    def client_headers(request: Request) -> list[tuple[str, str]]:
        """The client's headers that are forwarded upstream (the one filter both uses share)."""
        drop = set(_HOP_BY_HOP) | {GUARD_HEADER, "accept-encoding", "cookie", "proxy-connection"}
        # RFC 9110 7.6.1: headers named in Connection are hop-by-hop too.
        for value in request.headers.getlist("connection"):
            drop |= {t.strip().lower() for t in value.split(",") if t.strip()}
        if cfg.credential_mode != "passthrough":
            drop |= {"authorization", "x-api-key"}
        return [(k, v) for k, v in request.headers.items() if k.lower() not in drop]

    def upstream_headers(request: Request, adapter: Adapter) -> list[tuple[str, str]]:
        out = client_headers(request)
        if cfg.credential_mode == "gateway" and cfg.upstream_credential:
            if adapter.format == "anthropic":
                out.append(("x-api-key", cfg.upstream_credential))
            else:
                out.append(("authorization", f"Bearer {cfg.upstream_credential}"))
        return out

    def response_headers(resp: httpx.Response) -> dict[str, str]:
        return {k: v for k, v in resp.headers.items() if k.lower() not in _DROP_RESPONSE}

    def override_possible(decision: Decision) -> bool:
        """A human prompt is only offered when nothing in the request is block-hard."""
        return (
            channel is not None
            and not cfg.headless
            and all(b.action != Action.BLOCK_HARD for b in decision.blocked)
        )

    def record(
        decision: Decision, request_hash: str, leftover: int = 0, action: str | None = None
    ) -> None:
        offered = [
            {"id": b.override_id, "rule_id": b.rule_id, "status": "offered"}
            for b in decision.blocked
            if b.override_id and override_possible(decision)
        ]
        audit.record(
            agent=cfg.agent, lane=lane.name, trust=lane.trust, decision=decision,
            request_hash=request_hash, overrides=offered, leftover_count=leftover,
            action=action,
        )  # fmt: skip

    async def arecord(
        decision: Decision, request_hash: str, leftover: int = 0, action: str | None = None
    ) -> bool:
        """Write the audit record off the event loop; False when it could not be written."""
        try:
            await asyncio.to_thread(record, decision, request_hash, leftover, action)
        except AuditUnavailable:
            return False
        return True

    def audit_down(adapter: Adapter, what: str) -> Response:
        return JSONResponse(
            adapter.error_body(f"cui-guard blocked this {what}: audit log unavailable."),
            status_code=adapter.block_status,
        )

    def audit_failed_late() -> None:
        """The record could not be written after output had started: say so, never stay silent."""
        sys.stderr.write("cui-guard: audit record could not be written for a streamed response\n")
        sys.stderr.flush()
        if channel is not None:
            info = BlockInfo(
                "audit.unavailable", DetClass.UNPARSEABLE, Action.BLOCK_HARD, "audit",
                "audit record could not be written", "", None,
            )  # fmt: skip
            notify(channel.notify_block, info, False)

    async def blocked_response(adapter: Adapter, decision: Decision, request_hash: str) -> Response:
        offered = override_possible(decision)
        msg = _block_message(decision, offered, messages, policy.poc)
        if not await arecord(decision, request_hash):
            msg = "cui-guard blocked this request: audit log unavailable."
        if channel is not None:
            for b in decision.blocked:
                if offered and b.override_id is not None and b.action == Action.BLOCK:
                    start_override_flow(b)
                else:
                    notify(channel.notify_block, b, False)
        return JSONResponse(adapter.error_body(msg), status_code=adapter.block_status)

    async def hello(request: Request) -> Response:
        return Response(status_code=200)

    async def count_tokens(request: Request) -> Response:
        if not authorized(request):
            return Response(status_code=401)
        try:
            raw = await read_capped(request)
        except BodyTooLarge:
            return JSONResponse(adapters["anthropic"].error_body(_TOO_LARGE), status_code=413)
        await arecord(Decision(), hashlib.sha256(raw).hexdigest(), action="rejected")
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
            try:
                raw = await read_capped(request)
            except BodyTooLarge:
                return JSONResponse(adapter.error_body(_TOO_LARGE), status_code=413)
            request_hash = hashlib.sha256(raw).hexdigest()
            if adapter.format not in lane.formats:
                await arecord(Decision(), request_hash, action="rejected")
                return JSONResponse(
                    adapter.error_body(
                        f"cui-guard: lane {lane.name!r} does not accept the {adapter.format!r} format"
                    ),
                    status_code=400,
                )
            try:
                body = json.loads(raw)
            except (ValueError, RecursionError):
                body = None
            if not isinstance(body, dict):
                decision = _fail_block("unparseable", "request", "request body is not a JSON object")
                return await blocked_response(adapter, decision, request_hash)
            try:
                view = adapter.extract(body)
                # Credentials and content-type are not scanned: the first belong to the
                # client's login (or the gateway), the second is set by the gateway.
                view.headers = [
                    Segment(i, f"header:{k.lower()}", v)
                    for i, (k, v) in enumerate(client_headers(request))
                    if k.lower() not in ("authorization", "x-api-key", "content-type")
                ]
                # The query string is forwarded too and cannot be rewritten: scan the raw
                # and the percent-decoded forms like a header (a hit blocks the request).
                query = request.url.query
                if query:
                    forms = dict.fromkeys((query, unquote_plus(query), unquote_plus(unquote_plus(query))))
                    view.headers += [
                        Segment(len(view.headers) + j, "header:query", f)
                        for j, f in enumerate(forms)
                    ]
                decision = await asyncio.to_thread(pipeline.evaluate, view)
                if decision.forward:
                    out_bytes = json.dumps(
                        adapter.apply(body, decision), ensure_ascii=False
                    ).encode("utf-8")
            except Exception as e:  # noqa: BLE001 - fail closed
                decision = _fail_block("internal.error", "request", type(e).__name__)
            if not decision.forward:
                return await blocked_response(adapter, decision, request_hash)
            try:
                await asyncio.to_thread(audit.preflight)
            except AuditUnavailable:
                return audit_down(adapter, "request")
            url = base_url + request.url.path
            if request.url.query:
                url += "?" + request.url.query
            headers = [(k, v) for k, v in upstream_headers(request, adapter) if k.lower() != "content-type"]
            headers.append(("content-type", "application/json"))
            req = client.build_request("POST", url, headers=headers, content=out_bytes)
            if body.get("stream") is True:
                return await stream_path(adapter, req, decision, request_hash)
            return await plain_path(adapter, req, decision, request_hash)

        return handle

    async def send_upstream(adapter: Adapter, req: httpx.Request, stream: bool):
        try:
            resp = await client.send(req, stream=stream)
        except Exception:  # noqa: BLE001
            return None, JSONResponse(
                adapter.error_body("cui-guard: upstream request failed"), status_code=502
            )
        if 300 <= resp.status_code < 400:
            # Never relay a redirect: the agent's own client would follow its Location.
            await resp.aclose()
            return None, JSONResponse(
                adapter.error_body("cui-guard: upstream answered with a redirect"), status_code=502
            )
        return resp, None

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
        withheld = smap.take_withheld()
        if not await arecord(decision, request_hash, leftover):
            return audit_down(adapter, "response")
        if withheld and not await arecord(
            _withheld_decision(withheld), request_hash, action="withheld"
        ):
            return audit_down(adapter, "response")
        notify_leftover(leftover + withheld)
        return result

    async def stream_path(adapter, req, decision, request_hash) -> Response:
        resp, err = await send_upstream(adapter, req, True)
        if err is not None:
            if not await arecord(decision, request_hash):
                return audit_down(adapter, "response")
            return err
        if resp.status_code >= 400:
            content = await resp.aread()
            await resp.aclose()
            if not await arecord(decision, request_hash):
                return audit_down(adapter, "response")
            return Response(content, resp.status_code, response_headers(resp))

        def keepalive_bytes() -> bytes:
            ka = adapter.keepalive()
            return ka if isinstance(ka, bytes) else encode_event(ka)

        async def gen() -> AsyncIterator[bytes]:
            rewriter = adapter.stream_rewriter(smap)
            decoder = SSEDecoder()
            it = resp.aiter_bytes().__aiter__()
            nxt: asyncio.Future | None = None
            last_down = time.monotonic()  # when a byte last went downstream

            def ping_due() -> bool:
                return rewriter.pending and time.monotonic() - last_down >= PING_INTERVAL_S

            try:
                try:
                    while True:
                        nxt = asyncio.ensure_future(it.__anext__())
                        while True:
                            done, _ = await asyncio.wait({nxt}, timeout=PING_INTERVAL_S)
                            if done:
                                break
                            if ping_due():
                                yield keepalive_bytes()
                                last_down = time.monotonic()
                        try:
                            chunk = nxt.result()
                        except StopAsyncIteration:
                            nxt = None
                            break
                        nxt = None
                        for ev in decoder.feed(chunk):
                            for out in rewriter.feed(ev):
                                yield encode_event(out)
                                last_down = time.monotonic()
                        if ping_due():
                            yield keepalive_bytes()
                            last_down = time.monotonic()
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
                leftover = _leftover_from_notes(rewriter.notes)
                withheld = smap.take_withheld()
                try:
                    recorded = await arecord(decision, request_hash, leftover)
                    if recorded and withheld:
                        recorded = await arecord(
                            _withheld_decision(withheld), request_hash, action="withheld"
                        )
                except Exception:  # noqa: BLE001 - never skip closing upstream or the notices
                    recorded = False
                if not recorded:
                    audit_failed_late()
                await resp.aclose()
                notify_leftover(leftover + withheld)

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
    app = Starlette(routes=routes, lifespan=lifespan)
    app.add_middleware(LoopbackGuard)
    app.state.client = client
    return app
