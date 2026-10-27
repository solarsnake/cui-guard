"""Egress recorder for the leak suite: logs every name lookup and socket connect.

Loaded automatically by the gateway subprocess when this directory is on PYTHONPATH.
Active only when CUI_GUARD_EGRESS_LOG names a file; one JSON line per call:
{"op": "getaddrinfo" | "connect", "host": ..., "port": ...}.
"""

from __future__ import annotations

import json
import os
import socket

_LOG = os.environ.get("CUI_GUARD_EGRESS_LOG")


def _record(op: str, host: object, port: object) -> None:
    line = json.dumps({"op": op, "host": str(host), "port": port}) + "\n"
    fd = os.open(str(_LOG), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode())
    finally:
        os.close(fd)


if _LOG:
    _real_getaddrinfo = socket.getaddrinfo
    _real_connect = socket.socket.connect

    def _getaddrinfo(host, port, *args, **kwargs):
        _record("getaddrinfo", host, port if isinstance(port, int) else str(port))
        return _real_getaddrinfo(host, port, *args, **kwargs)

    def _connect(self, address):
        if isinstance(address, tuple) and len(address) >= 2:  # AF_INET / AF_INET6
            _record("connect", address[0], address[1])
        else:  # AF_UNIX and friends
            _record("connect", address, None)
        return _real_connect(self, address)

    socket.getaddrinfo = _getaddrinfo
    socket.socket.connect = _connect
