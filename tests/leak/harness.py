"""Test harness: a recording fake upstream (real uvicorn) and a real gateway subprocess."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import uvicorn
from canaries import PATHS, USER_POLICY_IDENTIFIERS
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route

from cui_guard.launch import session as session_mod
from cui_guard.launch.session import GatewaySession, prepare_policy, start_gateway
from cui_guard.override.human import FakeChannel
from cui_guard.policy import loader

TOKEN_HEADER = "x-cui-guard-token"


@dataclass
class Rec:
    path: str
    body: bytes
    headers: dict[str, str]
    query: str = ""


Responder = Callable[[str, bytes, bool], bytes | None]


def _sse(events: list[tuple[str | None, dict | str]]) -> bytes:
    out = []
    for name, data in events:
        payload = data if isinstance(data, str) else json.dumps(data)
        out.append((f"event: {name}\n" if name else "") + f"data: {payload}\n\n")
    return "".join(out).encode()


def text_response(fmt: str, stream: bool, text: str = "ok") -> tuple[str, bytes]:
    """(content_type, body) for a plain text reply."""
    if fmt == "anthropic":
        if not stream:
            body = {"id": "msg_1", "type": "message", "role": "assistant", "model": "m",
                    "content": [{"type": "text", "text": text}], "stop_reason": "end_turn",
                    "usage": {"input_tokens": 1, "output_tokens": 1}}  # fmt: skip
            return "application/json", json.dumps(body).encode()
        return "text/event-stream", _sse([
            ("message_start", {"type": "message_start", "message": {
                "id": "msg_1", "type": "message", "role": "assistant", "content": [], "model": "m"}}),
            ("content_block_start", {"type": "content_block_start", "index": 0,
                                     "content_block": {"type": "text", "text": ""}}),
            ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                     "delta": {"type": "text_delta", "text": text}}),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"},
                               "usage": {"output_tokens": 1}}),
            ("message_stop", {"type": "message_stop"}),
        ])  # fmt: skip
    if fmt == "openai-responses":
        item = {"type": "message", "role": "assistant", "id": "m1",
                "content": [{"type": "output_text", "text": text}]}  # fmt: skip
        if not stream:
            body = {"id": "r1", "object": "response", "status": "completed", "output": [item]}
            return "application/json", json.dumps(body).encode()
        base = {"item_id": "m1", "output_index": 0, "content_index": 0}
        return "text/event-stream", _sse([
            ("response.output_text.delta", {"type": "response.output_text.delta", **base, "delta": text}),
            ("response.output_text.done", {"type": "response.output_text.done", **base, "text": text}),
            ("response.completed", {"type": "response.completed", "response": {
                "id": "r1", "status": "completed", "output": [item]}}),
        ])  # fmt: skip
    if not stream:
        body = {"id": "c1", "object": "chat.completion", "model": "m", "choices": [
            {"index": 0, "finish_reason": "stop",
             "message": {"role": "assistant", "content": text}}]}  # fmt: skip
        return "application/json", json.dumps(body).encode()
    return "text/event-stream", _sse([
        (None, _chat_chunk({"role": "assistant", "content": text})),
        (None, _chat_chunk({}, "stop")),
        (None, "[DONE]"),
    ])


def _chat_chunk(delta: dict, finish: str | None = None) -> dict:
    return {"id": "c1", "object": "chat.completion.chunk", "model": "m",
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}  # fmt: skip


def tool_call_response(fmt: str, stream: bool, command: str) -> tuple[str, bytes]:
    """(content_type, body) for a reply that asks the client to run `command`."""
    args = json.dumps({"command": command})
    cut = len(args) // 2
    if fmt == "anthropic":
        if not stream:
            body = {"id": "msg_2", "type": "message", "role": "assistant", "model": "m",
                    "content": [{"type": "tool_use", "id": "toolu_9", "name": "run",
                                 "input": {"command": command}}],
                    "stop_reason": "tool_use"}  # fmt: skip
            return "application/json", json.dumps(body).encode()
        delta = "content_block_delta"
        return "text/event-stream", _sse([
            ("message_start", {"type": "message_start", "message": {
                "id": "msg_2", "type": "message", "role": "assistant", "content": [], "model": "m"}}),
            ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {
                "type": "tool_use", "id": "toolu_9", "name": "run", "input": {}}}),
            (delta, {"type": delta, "index": 0,
                     "delta": {"type": "input_json_delta", "partial_json": args[:cut]}}),
            (delta, {"type": delta, "index": 0,
                     "delta": {"type": "input_json_delta", "partial_json": args[cut:]}}),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use"},
                               "usage": {"output_tokens": 1}}),
            ("message_stop", {"type": "message_stop"}),
        ])  # fmt: skip
    if fmt == "openai-responses":
        item = {"type": "function_call", "id": "fc1", "call_id": "c9", "name": "run",
                "arguments": args}  # fmt: skip
        if not stream:
            body = {"id": "r2", "object": "response", "status": "completed", "output": [item]}
            return "application/json", json.dumps(body).encode()
        ref = {"item_id": "fc1", "output_index": 0}
        d = "response.function_call_arguments.delta"
        return "text/event-stream", _sse([
            ("response.output_item.added", {"type": "response.output_item.added", "output_index": 0,
                                            "item": {**item, "arguments": ""}}),
            (d, {"type": d, **ref, "delta": args[:cut]}),
            (d, {"type": d, **ref, "delta": args[cut:]}),
            ("response.function_call_arguments.done", {
                "type": "response.function_call_arguments.done", **ref, "arguments": args}),
            ("response.output_item.done", {"type": "response.output_item.done",
                                           "output_index": 0, "item": item}),
            ("response.completed", {"type": "response.completed", "response": {
                "id": "r2", "status": "completed", "output": [item]}}),
        ])  # fmt: skip
    call = {"id": "call_9", "type": "function", "function": {"name": "run", "arguments": args}}
    if not stream:
        body = {"id": "c2", "object": "chat.completion", "model": "m", "choices": [
            {"index": 0, "finish_reason": "tool_calls",
             "message": {"role": "assistant", "content": None, "tool_calls": [call]}}]}  # fmt: skip
        return "application/json", json.dumps(body).encode()

    def tc(function: dict, **extra) -> dict:
        return _chat_chunk({"tool_calls": [{"index": 0, **extra, "function": function}]})

    return "text/event-stream", _sse([
        (None, tc({"name": "run", "arguments": ""}, id="call_9", type="function")),
        (None, tc({"arguments": args[:cut]})),
        (None, tc({"arguments": args[cut:]})),
        (None, _chat_chunk({}, "tool_calls")),
        (None, "[DONE]"),
    ])  # fmt: skip


class FakeUpstream:
    """A real HTTP server on 127.0.0.1 that records every request byte."""

    def __init__(self) -> None:
        self.records: list[Rec] = []
        self.responder: Callable[[str, str, bytes, bool], tuple[str, bytes]] | None = None
        self.status = 200
        self._fmt_by_path = {p: f for f, p in PATHS.items()}
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self.port = 0

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    async def _handle(self, request: Request) -> Response:
        raw = await request.body()
        path = request.url.path
        self.records.append(Rec(path, raw, dict(request.headers), request.url.query))
        fmt = self._fmt_by_path.get(path, "anthropic")
        try:
            stream = json.loads(raw).get("stream") is True
        except ValueError:
            stream = False
        if self.responder is not None:
            ctype, body = self.responder(fmt, path, raw, stream)
        else:
            ctype, body = text_response(fmt, stream)
        if ctype == "text/event-stream":
            async def gen():
                yield body

            return StreamingResponse(gen(), media_type=ctype, status_code=self.status)
        return Response(body, media_type=ctype, status_code=self.status)

    def start(self) -> None:
        app = Starlette(routes=[Route("/{path:path}", self._handle, methods=["POST"])])
        cfg = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error", access_log=False)
        self._server = uvicorn.Server(cfg)
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("fake upstream did not start")
            time.sleep(0.02)
        self.port = self._server.servers[0].sockets[0].getsockname()[1]

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=5)

    def reset(self) -> None:
        self.records.clear()
        self.responder = None
        self.status = 200

    def all_bytes(self) -> bytes:
        """Path, query, header and body bytes of every record."""
        parts: list[bytes] = []
        for r in self.records:
            heads = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            parts += [r.path.encode(), r.query.encode(), heads.encode(), r.body]
        return b"\n".join(parts)


def write_user_config(
    config_home: Path,
    upstream_url: str,
    trust: str,
    credential: str = "none",
    extra: str = "",
) -> Path:
    path = config_home / "cui-guard" / "config.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    ids = ", ".join(json.dumps(v) for v in USER_POLICY_IDENTIFIERS["codenames"])
    people = ", ".join(json.dumps(v) for v in USER_POLICY_IDENTIFIERS["people"])
    path.write_text(
        'default_lane = "fake"\n\n'
        "[endpoints.fake]\n"
        f'url = "{upstream_url}"\n'
        'formats = ["anthropic", "openai-responses", "openai-chat"]\n'
        f'trust = "{trust}"\n'
        f'credential = "{credential}"\n\n'
        f"[identifiers]\ncodenames = [{ids}]\npeople = [{people}]\n" + extra,
        encoding="utf-8",
    )
    return path


@dataclass
class Dirs:
    root: Path
    config: Path = field(init=False)
    state: Path = field(init=False)
    home: Path = field(init=False)

    def __post_init__(self) -> None:
        self.config = self.root / "config"
        self.state = self.root / "state"
        self.home = self.root / "home"
        for d in (self.config, self.state, self.home):
            d.mkdir(parents=True, exist_ok=True)

    def env(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        env = dict(os.environ)
        env.update(HOME=str(self.home), XDG_CONFIG_HOME=str(self.config),
                   XDG_STATE_HOME=str(self.state))  # fmt: skip
        env.pop("NO_COLOR", None)
        env.update(extra or {})
        return env

    @property
    def audit_path(self) -> Path:
        return self.state / "cui-guard" / "audit.jsonl"


class Gateway:
    """A real gateway subprocess plus a small HTTP client for it."""

    def __init__(self, session: GatewaySession, dirs: Dirs) -> None:
        self.session = session
        self.dirs = dirs
        self.base = f"http://127.0.0.1:{session.port}"
        self.token = session.token
        self.client = httpx.Client(trust_env=False, timeout=30)
        self.egress_path = dirs.root / "egress.jsonl"
        self._out: list[str] = []
        proc = session.proc
        if proc.stdout is not None:
            threading.Thread(target=self._drain, args=(proc.stdout, None), daemon=True).start()
        if proc.stderr is not None:
            # Record stderr and relay it to ours, so tests that watch fd 2 still see it.
            threading.Thread(target=self._drain, args=(proc.stderr, 2), daemon=True).start()

    def _drain(self, stream, relay_fd: int | None) -> None:
        try:
            for line in stream:
                self._out.append(line)
                if relay_fd is not None:
                    os.write(relay_fd, line.encode())
        except (OSError, ValueError):
            pass

    def egress_log(self) -> list[dict]:
        """Every name lookup and socket connect the gateway process made."""
        if not self.egress_path.exists():
            return []
        lines = self.egress_path.read_text(encoding="utf-8").splitlines()
        return [json.loads(x) for x in lines if x.strip()]

    def output(self) -> str:
        """Captured stdout and stderr of the gateway process."""
        time.sleep(0.2)  # let the drain thread catch up
        return "".join(self._out)

    def post(self, path: str, body: dict | bytes, token: str | None = "", headers=None):
        """POST to the gateway. token "" means the real token, None means no token header."""
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        hdrs = {"content-type": "application/json", **(headers or {})}
        if token is not None:
            hdrs[TOKEN_HEADER] = token or self.token
        return self.client.post(self.base + path, content=raw, headers=hdrs)

    def close(self) -> None:
        self.client.close()
        self.session.close()


def launch_gateway(
    dirs: Dirs,
    upstream_url: str,
    trust: str,
    credential: str = "none",
    extra_env: dict[str, str] | None = None,
    extra_config: str = "",
) -> Gateway:
    """Write the user policy, approve it once (fake channel), start a real gateway."""
    import pytest

    write_user_config(dirs.config, upstream_url, trust, credential, extra_config)
    hook = str(Path(__file__).resolve().parent / "egress_hook")
    base_env = dict(os.environ)
    path = hook + (os.pathsep + base_env["PYTHONPATH"] if base_env.get("PYTHONPATH") else "")
    env = dirs.env({"PYTHONPATH": path, "CUI_GUARD_EGRESS_LOG": str(dirs.root / "egress.jsonl"),
                    **(extra_env or {})})  # fmt: skip
    real_popen = subprocess.Popen

    def popen_with_stderr(*args, **kwargs):
        return real_popen(*args, stderr=subprocess.PIPE, **kwargs)

    with pytest.MonkeyPatch.context() as mp:
        for k in ("HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME"):
            mp.setenv(k, env[k])
        mp.setattr(session_mod.subprocess, "Popen", popen_with_stderr)
        mp.setattr(loader, "org_policy_path", lambda: dirs.root / "no-org-policy.toml")
        # A user-defined default lane is a loosening, so every launch needs approval:
        # approve as the human would, then run the gateway headless on that approval.
        policy = prepare_policy(False, FakeChannel(None, auth_ok=True))
        mp.setattr(session_mod, "prepare_policy", lambda headless, channel: policy)
        session = start_gateway("generic", "fake", True, env, channel=FakeChannel(None, True))
    return Gateway(session, dirs)
