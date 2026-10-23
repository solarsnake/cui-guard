"""Append-only JSONL audit log. Never records real values or raw content."""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import logging.handlers
import os
import threading
from datetime import UTC, datetime

from cui_guard import __version__
from cui_guard.model import Trust
from cui_guard.pipeline import Decision
from cui_guard.policy.schema import AuditConfig


class AuditUnavailable(Exception):
    """The audit sink failed and policy says to block rather than buffer."""


class _StrictSysLogHandler(logging.handlers.SysLogHandler):
    def handleError(self, record: logging.LogRecord) -> None:
        raise  # noqa: PLE0704 - re-raise the emit failure to the caller


def _syslog_address(spec: str) -> str | tuple[str, int]:
    if not spec:
        return "/dev/log"
    if spec.startswith("/"):
        return spec
    host, _, port = spec.rpartition(":")
    if host and port.isdigit():
        return (host, int(port))
    return (spec, 514)


def sha256_json(obj: object) -> str:
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, cfg: AuditConfig, session_id: str, policy_hash: str = "") -> None:
        self._cfg = cfg
        self._session = session_id
        self._policy_hash = policy_hash
        self._path = os.path.expanduser(cfg.path)
        self._pending_path = self._path + ".pending"
        self._lock = threading.Lock()
        self._syslog: logging.Handler | None = None

    def set_policy_hash(self, value: str) -> None:
        self._policy_hash = value

    def _append(self, path: str, line: str) -> None:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, (line + "\n").encode("utf-8"))
        finally:
            os.close(fd)

    def _send_sink(self, line: str) -> None:
        sink = self._cfg.sink
        if not sink:
            return
        if not sink.startswith("syslog:"):
            raise OSError(f"unsupported audit sink: {sink.split(':', 1)[0]}")
        if self._syslog is None:
            self._syslog = _StrictSysLogHandler(address=_syslog_address(sink[len("syslog:") :]))
        rec = logging.LogRecord("cui-guard", logging.INFO, "", 0, line, None, None)
        self._syslog.handle(rec)

    def preflight(self) -> None:
        """In block mode, raise AuditUnavailable if the local file cannot be appended to."""
        if self._cfg.on_sink_failure != "block":
            return
        try:
            self._append(self._path, "")
        except OSError as e:
            raise AuditUnavailable("audit log unavailable") from e

    def record(
        self,
        *,
        agent: str,
        lane: str,
        trust: Trust,
        decision: Decision,
        request_hash: str,
        overrides: list[dict] | None = None,
        leftover_count: int = 0,
    ) -> None:
        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "session": self._session,
            "agent": agent,
            "lane": lane,
            "trust": str(trust.value),
            "hits": dict(decision.hit_counts),
            "action": "blocked" if decision.blocked else "forwarded",
            "blocked_rules": [b.rule_id for b in decision.blocked],
            "override": overrides[0] if overrides else None,
            "leftover_count": leftover_count,
            "request_hash": request_hash,
            "guard_version": __version__,
            "policy_hash": self._policy_hash,
        }
        line = json.dumps(entry, separators=(",", ":"), default=str)
        with self._lock:
            failed = False
            try:
                self._append(self._path, line)
                self._send_sink(line)
            except Exception as e:
                failed = True
                if self._cfg.on_sink_failure == "block":
                    raise AuditUnavailable("audit sink unavailable") from e
                try:
                    self._append(self._pending_path, line)
                except OSError as e2:
                    raise AuditUnavailable("audit log unavailable") from e2
            finally:
                if failed and self._syslog is not None:
                    with contextlib.suppress(Exception):
                        self._syslog.close()
                    self._syslog = None
