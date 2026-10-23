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


MAX_JUSTIFICATION_CHARS = 500
_OVERRIDE_KEYS = ("id", "rule_id", "status", "content_hash", "justification")


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


def _override_entry(o: dict) -> dict:
    entry = {k: o[k] for k in _OVERRIDE_KEYS if k in o}
    if isinstance(entry.get("justification"), str):
        entry["justification"] = entry["justification"][:MAX_JUSTIFICATION_CHARS]
    return entry


class AuditLog:
    def __init__(self, cfg: AuditConfig, session_id: str, policy_hash: str = "") -> None:
        self._cfg = cfg
        self._session = session_id
        self._policy_hash = policy_hash
        self._path = os.path.expanduser(cfg.path)
        self._pending_path = self._path + ".pending"
        self._lock = threading.Lock()
        self._syslog: logging.Handler | None = None
        if cfg.sink and not cfg.sink.startswith("syslog:"):
            raise ValueError(f"unsupported audit sink scheme: {cfg.sink.split(':', 1)[0]!r}")

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

    def _handler(self) -> logging.Handler:
        sink = self._cfg.sink or ""
        if self._syslog is None:
            self._syslog = _StrictSysLogHandler(address=_syslog_address(sink[len("syslog:") :]))
        return self._syslog

    def _drop_handler(self) -> None:
        if self._syslog is not None:
            with contextlib.suppress(Exception):
                self._syslog.close()
            self._syslog = None

    def _emit(self, line: str) -> None:
        rec = logging.LogRecord("cui-guard", logging.INFO, "", 0, line, None, None)
        self._handler().handle(rec)

    def _send_sink(self, line: str) -> None:
        if not self._cfg.sink:
            return
        self._emit(line)
        self._drain_pending()

    def _drain_pending(self) -> None:
        """Best effort: replay buffered lines to the sink, then truncate the buffer."""
        try:
            if not os.path.exists(self._pending_path):
                return
            with open(self._pending_path, encoding="utf-8") as f:
                lines = [x for x in f.read().splitlines() if x]
            for ln in lines:
                self._emit(ln)
            open(self._pending_path, "w").close()
        except Exception:  # noqa: BLE001 - the buffer stays for the next attempt
            return

    def preflight(self) -> None:
        """Raise AuditUnavailable unless a record could be written. Writes nothing."""
        with self._lock:
            try:
                d = os.path.dirname(self._path)
                if d:
                    os.makedirs(d, mode=0o700, exist_ok=True)
                os.close(os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600))
            except OSError as e:
                raise AuditUnavailable("audit log unavailable") from e
            if self._cfg.on_sink_failure == "block" and self._cfg.sink:
                try:
                    handler = self._handler()
                    sock = getattr(handler, "socket", None)
                    if sock is None or sock.fileno() < 0:
                        handler.createSocket()  # type: ignore[attr-defined]
                        sock = getattr(handler, "socket", None)
                    if sock is None or sock.fileno() < 0:
                        raise OSError("audit sink not connected")
                except Exception as e:
                    self._drop_handler()
                    raise AuditUnavailable("audit sink unavailable") from e

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
        action: str | None = None,
    ) -> None:
        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "session": self._session,
            "agent": agent,
            "lane": lane,
            "trust": str(trust.value),
            "hits": dict(decision.hit_counts),
            "action": action or ("blocked" if decision.blocked else "forwarded"),
            "blocked_rules": [b.rule_id for b in decision.blocked],
            "override": [_override_entry(o) for o in (overrides or [])],
            "leftover_count": leftover_count,
            "request_hash": request_hash,
            "guard_version": __version__,
            "policy_hash": self._policy_hash,
        }
        line = json.dumps(entry, separators=(",", ":"), default=str)
        with self._lock:
            try:
                self._append(self._path, line)
                self._send_sink(line)
            except Exception as e:
                self._drop_handler()
                if self._cfg.on_sink_failure == "block":
                    raise AuditUnavailable("audit sink unavailable") from e
                try:
                    self._append(self._pending_path, line)
                except OSError as e2:
                    raise AuditUnavailable("audit log unavailable") from e2
