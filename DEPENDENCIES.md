# Runtime dependencies

The runtime closure is pinned and hash-locked in `uv.lock`, which holds a hash for every artifact. `scripts/check` exports it to `build/locks/runtime.lock.txt` (generated, not committed), and the release publishes that file as `runtime.lock.txt`. Direct dependencies are `starlette`, `uvicorn` and `httpx`; everything else is transitive. Dev tooling lives in the `dev` dependency group and is not part of the runtime closure.

| Package | Why it is needed | What it touches |
|---|---|---|
| starlette | ASGI framework for the local gateway routes | network (loopback listener, via uvicorn) |
| uvicorn | ASGI server that binds the gateway to 127.0.0.1 | network (loopback socket) |
| httpx | HTTP client that forwards cleaned requests to the upstream LLM endpoint | network (outbound HTTPS) |
| httpcore | Transport layer under httpx | network |
| h11 | HTTP/1.1 protocol parser used by httpcore and uvicorn | nothing (pure protocol code) |
| anyio | Async I/O abstraction used by starlette and httpx | network, filesystem (event loop, sockets) |
| idna | Internationalized domain name encoding for httpx | nothing |
| certifi | CA certificate bundle for upstream TLS verification | filesystem (reads the bundle) |
| click | Command-line handling for uvicorn | nothing |
| typing-extensions | Typing backports used by anyio and starlette | nothing |

## Rule for new dependencies

A new runtime dependency needs a row in the table above and a reviewer's sign-off before it is merged. The lock files must be regenerated in the same change, and `scripts/check lock` must pass.
