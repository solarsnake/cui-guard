"""Run the gateway: read GatewayConfig JSON on stdin, serve on loopback, print READY <port>."""

from __future__ import annotations

import asyncio
import sys

import uvicorn

from cui_guard.gateway.app import GatewayConfig, create_app
from cui_guard.override.human import load_messages, select_channel


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


def main() -> None:
    cfg = GatewayConfig.from_json(sys.stdin.read())
    asyncio.run(_serve(cfg))


if __name__ == "__main__":
    main()
