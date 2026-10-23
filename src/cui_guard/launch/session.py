"""Gateway session: policy confirmation, lane choice, gateway subprocess lifecycle."""

from __future__ import annotations

import json
import os
import queue
import re
import secrets
import subprocess
import sys
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Self

from cui_guard import __version__
from cui_guard.gateway.app import GatewayConfig
from cui_guard.override.human import select_channel
from cui_guard.policy.loader import load_effective_policy, state_dir
from cui_guard.policy.schema import EffectivePolicy, Endpoint, PolicyError
from cui_guard.policy.snapshot import (
    load_snapshot,
    loosenings,
    save_snapshot,
    snapshot_path,
)

READY_TIMEOUT_S = 10.0
STOP_TIMEOUT_S = 5.0
AGENT_FORMATS = {"claude": "anthropic", "codex": "openai-responses"}
AGENT_DEFAULT_LANES = {"claude": "anthropic", "codex": "openai"}


class LaunchError(Exception):
    pass


def version_tuple(text: str) -> tuple[int, ...]:
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", text)
    if not m:
        raise LaunchError(f"cannot parse version {text!r}")
    return tuple(int(p) for p in m.group(1).split("."))


def version_lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) < b + (0,) * (n - len(b))


def resolve_credential(ep: Endpoint, env: Mapping[str, str]) -> tuple[str, str | None]:
    """Return (mode, secret) for an endpoint's credential spec."""
    kind, _, arg = ep.credential.partition(":")
    if kind == "none":
        return "none", None
    if kind == "env-or-passthrough":
        value = env.get(arg)
        return ("gateway", value) if value else ("passthrough", None)
    if kind == "env":
        value = env.get(arg)
        if not value:
            raise LaunchError(f"endpoint {ep.name}: environment variable {arg} is not set")
        return "gateway", value
    if kind == "keychain":
        service, _, account = arg.partition("/")
        if not service or not account:
            raise LaunchError(f"endpoint {ep.name}: bad keychain spec {ep.credential!r}")
        if sys.platform == "darwin":
            cmd = ["security", "find-generic-password", "-s", service, "-a", account, "-w"]
        else:
            cmd = ["secret-tool", "lookup", "service", service, "account", account]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise LaunchError(f"endpoint {ep.name}: keychain lookup failed: {e}") from e
        secret = proc.stdout.rstrip("\n")
        if proc.returncode != 0 or not secret:
            raise LaunchError(f"endpoint {ep.name}: no keychain entry for {arg}")
        return "gateway", secret
    raise LaunchError(f"endpoint {ep.name}: unknown credential spec {ep.credential!r}")


def prepare_policy(headless: bool, channel) -> EffectivePolicy:
    """Load the policy; require human approval for settings looser than the last approved."""
    try:
        policy, user_layer = load_effective_policy()
    except PolicyError as e:
        raise LaunchError(f"policy error: {e}") from e
    if policy.min_version is not None and version_lt(
        version_tuple(__version__), version_tuple(policy.min_version)
    ):
        raise LaunchError(
            f"cui-guard {__version__} is older than the organization minimum "
            f"{policy.min_version}"
        )
    snap = snapshot_path()
    reasons = loosenings(load_snapshot(snap), user_layer)
    if reasons:
        listing = "; ".join(reasons)
        if headless:
            raise LaunchError(f"loosened settings need interactive approval: {listing}")
        if not channel.authenticate(f"cui-guard: approve loosened settings: {listing}"):
            raise LaunchError(f"loosened settings were not approved: {listing}")
    save_snapshot(snap, user_layer)
    return policy


def choose_lane(policy: EffectivePolicy, agent: str, lane_name: str | None) -> Endpoint:
    fmt = AGENT_FORMATS.get(agent)

    def supports(ep: Endpoint) -> bool:
        return fmt is None or fmt in ep.formats

    if lane_name is not None:
        ep = policy.endpoints.get(lane_name)
        if ep is None:
            raise LaunchError(f"unknown lane {lane_name!r}; known: {sorted(policy.endpoints)}")
        if not supports(ep):
            raise LaunchError(f"lane {lane_name} does not support the {fmt} format used by {agent}")
        return ep
    for name in (policy.default_lane, AGENT_DEFAULT_LANES.get(agent)):
        ep = policy.endpoints.get(name) if name else None
        if ep is not None and supports(ep):
            return ep
    for name in sorted(policy.endpoints):
        if supports(policy.endpoints[name]):
            return policy.endpoints[name]
    raise LaunchError(f"no configured lane supports the {fmt} format used by {agent}")


@dataclass
class GatewaySession:
    port: int
    token: str
    session_id: str
    lane: Endpoint
    credential_mode: str
    proc: subprocess.Popen
    policy: EffectivePolicy | None = None
    session_file: Path | None = None
    agent: str = ""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        proc = self.proc
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=STOP_TIMEOUT_S)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        finally:
            if proc.stdout is not None:
                proc.stdout.close()
            if self.session_file is not None:
                self.session_file.unlink(missing_ok=True)


def _gateway_env(env: Mapping[str, str]) -> dict[str, str]:
    """Environment for the gateway process; upstream keys travel on stdin only."""
    return {k: v for k, v in env.items() if "API_KEY" not in k and "AUTH_TOKEN" not in k}


def _read_ready(proc: subprocess.Popen) -> int:
    q: queue.Queue[str] = queue.Queue()

    def reader() -> None:
        assert proc.stdout is not None
        try:
            q.put(proc.stdout.readline())
        except (OSError, ValueError):
            q.put("")

    threading.Thread(target=reader, daemon=True).start()
    try:
        line = q.get(timeout=READY_TIMEOUT_S)
    except queue.Empty:
        raise LaunchError("gateway did not become ready within 10 seconds") from None
    m = re.fullmatch(r"READY (\d+)\s*", line)
    if not m:
        raise LaunchError("gateway failed to start (see its output above)")
    return int(m.group(1))


def _write_session_file(s: GatewaySession) -> Path:
    path = state_dir() / "sessions" / f"{s.session_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "pid": s.proc.pid,
        "port": s.port,
        "agent": s.agent,
        "lane": s.lane.name,
        "trust": s.lane.trust.value,
        "started": datetime.now(UTC).isoformat(),
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return path


def start_gateway(
    agent: str,
    lane_name: str | None,
    headless: bool,
    env: Mapping[str, str],
    channel=None,
) -> GatewaySession:
    if channel is None:
        channel = select_channel(headless)
    policy = prepare_policy(headless, channel)
    lane = choose_lane(policy, agent, lane_name)
    mode, secret = resolve_credential(lane, env)
    token = secrets.token_urlsafe(32)
    session_id = secrets.token_hex(8)
    try:
        cfg = GatewayConfig(token, agent, lane, policy, mode, secret, headless, session_id)  # type: ignore[arg-type]
    except ValueError as e:
        raise LaunchError(str(e)) from e
    proc = subprocess.Popen(
        [sys.executable, "-m", "cui_guard.gateway"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        env=_gateway_env(env),
    )
    session = GatewaySession(0, token, session_id, lane, mode, proc, policy, agent=agent)
    try:
        assert proc.stdin is not None
        try:
            proc.stdin.write(cfg.to_json())
            proc.stdin.close()
        except OSError as e:
            raise LaunchError(f"gateway exited before reading its configuration: {e}") from e
        session.port = _read_ready(proc)
        session.session_file = _write_session_file(session)
    except BaseException:
        session.close()
        raise
    return session


def banner(session: GatewaySession, policy: EffectivePolicy) -> str:
    prov = policy.provenance
    layers = ", ".join(f"{k}={v}" for k, v in sorted(prov.items())) or "builtin"
    lines = [
        "cui-guard session",
        f"  lane:        {session.lane.name} ({session.lane.url})",
        f"  trust:       {session.lane.trust.value}",
        f"  credential:  {session.credential_mode}",
        f"  profile:     {policy.profile}",
        f"  settings from: {layers}",
    ]
    if session.credential_mode == "passthrough":
        lines += [
            "  Passthrough mode: the agent keeps its own login and the gateway forwards it",
            "  upstream. Trade-off (spec 13): the guard does not hold the credential, so it",
            "  cannot stop the agent from reaching the provider by a route that skips the",
            "  gateway.",
            "  Consumer-plan note: conversations on consumer plans may be used for model",
            "  training under the provider's data-use terms; check your plan settings.",
        ]
    return "\n".join(lines)
