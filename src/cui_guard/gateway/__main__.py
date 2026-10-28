"""Run the gateway: read GatewayConfig JSON on stdin, serve on loopback, print READY <port>."""

from __future__ import annotations

import asyncio
import os
import sys
import threading

import uvicorn

from cui_guard.fips import FipsError, require_fips
from cui_guard.gateway.app import GatewayConfig, create_app
from cui_guard.override.human import load_messages, select_channel
from cui_guard.policy.schema import PolicyError


async def _serve(cfg: GatewayConfig) -> None:
    messages = load_messages(cfg.policy.messages_file)
    channel = select_channel(cfg.headless, messages, cfg.policy.poc)
    app = create_app(cfg, channel=channel)
    config = uvicorn.Config(
        app, host="127.0.0.1", port=0, log_level="warning", access_log=False, lifespan="on"
    )
    server = uvicorn.Server(config)
    task = asyncio.ensure_future(server.serve())
    while not server.started:
        if task.done():
            await task
            return
        await asyncio.sleep(0.02)
    port = server.servers[0].sockets[0].getsockname()[1]
    sys.stdout.write(f"READY {port}\n")
    sys.stdout.flush()
    await task


def _watch_stdin(stream, exit_fn=os._exit) -> None:
    """Block until the launcher's end of stdin closes, then exit: no orphan gateways."""
    try:
        stream.read()
    except (OSError, ValueError):
        pass
    exit_fn(0)


def main() -> None:
    cfg = GatewayConfig.from_json(sys.stdin.readline())
    if cfg.policy.fips == "require":
        # Before anything listens: refuse unless the platform's validated module is in use.
        try:
            require_fips()
        except FipsError as e:
            sys.stderr.write(f"cui-guard gateway: fips = \"require\" but FIPS checks failed:\n{e}\n")
            sys.exit(1)
    threading.Thread(target=_watch_stdin, args=(sys.stdin,), daemon=True).start()
    try:
        asyncio.run(_serve(cfg))
    except PolicyError as e:  # e.g. a refused ca_file
        sys.stderr.write(f"cui-guard gateway: {e}\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
