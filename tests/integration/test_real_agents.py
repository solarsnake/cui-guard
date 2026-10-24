"""Smoke tests with the real agent CLIs. Skipped unless CUI_GUARD_REAL_AGENTS=1.

These start the real fake upstream and a real gateway through the real `cui-guard`
launcher, then run the installed agent against it. They use the agent's own login
(passthrough credential mode), so the fake upstream sees the agent's requests but the
guard never holds a credential.
"""

import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("CUI_GUARD_REAL_AGENTS") != "1", reason="set CUI_GUARD_REAL_AGENTS=1 to run"
)

sys.path.insert(0, str(Path(__file__).parent.parent / "leak"))
from harness import FakeUpstream, write_user_config

CLI = Path(sys.executable).parent / "cui-guard"
BYPASS_HOSTS = ("api.anthropic.com", "statsig", "datadoghq", "sentry")
PASSTHROUGH = "env-or-passthrough:CUI_GUARD_SMOKE_UNSET_KEY"


class RecordingProxy:
    """A tiny HTTP proxy that records every CONNECT / absolute-URI request target and refuses it."""

    def __init__(self) -> None:
        import asyncio

        self.targets: list[str] = []
        self.port = 0
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    async def _client(self, reader, writer) -> None:
        try:
            line = await reader.readline()
            parts = line.decode("latin-1").split()
            if len(parts) >= 2:
                self.targets.append(parts[1])
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
        except (OSError, ConnectionError):
            pass
        finally:
            writer.close()

    def _run(self) -> None:
        import asyncio

        asyncio.set_event_loop(self._loop)
        server = self._loop.run_until_complete(asyncio.start_server(self._client, "127.0.0.1", 0))
        self.port = server.sockets[0].getsockname()[1]
        self._ready.set()
        self._loop.run_forever()

    def start(self) -> None:
        self._thread.start()
        assert self._ready.wait(10)

    def stop(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)


@pytest.fixture
def upstream():
    up = FakeUpstream()
    up.start()
    yield up
    up.stop()


@pytest.fixture
def proxy():
    p = RecordingProxy()
    p.start()
    yield p
    p.stop()


def agent_env(tmp_path: Path, home: Path | None, proxy: RecordingProxy | None) -> dict[str, str]:
    env = dict(os.environ)
    env["XDG_CONFIG_HOME"] = str(tmp_path / "config")
    env["XDG_STATE_HOME"] = str(tmp_path / "state")
    env.pop("CUI_GUARD_SMOKE_UNSET_KEY", None)
    if home is not None:
        env["HOME"] = str(home)
    if proxy is not None:
        url = f"http://127.0.0.1:{proxy.port}"
        env.update(HTTPS_PROXY=url, HTTP_PROXY=url, https_proxy=url, http_proxy=url)
    return env


def run_launcher(agent: str, args: list[str], env: dict[str, str], cwd: Path, timeout=240):
    return subprocess.run(
        [str(CLI), agent, "--lane", "fake", "--headless", "--", *args],
        env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False,
    )  # fmt: skip


@pytest.mark.skipif(shutil.which("claude") is None, reason="claude is not installed")
def test_claude_routes_through_gateway(upstream, tmp_path):
    write_user_config(tmp_path / "config", upstream.url, "public", PASSTHROUGH)
    work = tmp_path / "work"
    work.mkdir()
    proc = run_launcher("claude", ["-p", "reply with the word ok"], agent_env(tmp_path, None, None), work)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert any(r.path.startswith("/v1/messages") for r in upstream.records), "no request reached the lane"
    assert "ok" in proc.stdout.lower()


@pytest.mark.skipif(shutil.which("claude") is None, reason="claude is not installed")
def test_claude_no_bypass_traffic(upstream, proxy, tmp_path):
    write_user_config(tmp_path / "config", upstream.url, "public", PASSTHROUGH)
    work = tmp_path / "work"
    work.mkdir()
    proc = run_launcher("claude", ["-p", "reply with the word ok"], agent_env(tmp_path, None, proxy), work)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert upstream.records, "no request reached the lane"
    print("proxy saw targets:", proxy.targets)
    bad = [t for t in proxy.targets if any(h in t.lower() for h in BYPASS_HOSTS)]
    assert not bad, f"traffic bypassed the gateway: {bad}"


@pytest.mark.skipif(shutil.which("claude") is None, reason="claude is not installed")
@pytest.mark.parametrize("where", ["project", "user"])
def test_claude_settings_file_base_url_does_not_win(upstream, tmp_path, where):
    """A settings-file ANTHROPIC_BASE_URL must not override the launcher's --settings value."""
    write_user_config(tmp_path / "config", upstream.url, "public", PASSTHROUGH)
    work = tmp_path / "work"
    work.mkdir()
    settings = {"env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:9"}}  # nothing listens here
    home = None
    if where == "project":
        (work / ".claude").mkdir()
        (work / ".claude" / "settings.json").write_text(json.dumps(settings))
    else:
        home = tmp_path / "home"
        (home / ".claude").mkdir(parents=True)
        (home / ".claude" / "settings.json").write_text(json.dumps(settings))
    proc = run_launcher("claude", ["-p", "reply with the word ok"], agent_env(tmp_path, home, None), work)
    detail = (proc.stdout + proc.stderr)[-1500:]
    if where == "user" and proc.returncode != 0 and not upstream.records:
        # Recorded in docs/LIMITS.md: an isolated HOME hides the macOS login keychain.
        pytest.skip(f"isolated HOME breaks Claude Code login on this machine: {detail}")
    assert proc.returncode == 0, detail
    assert upstream.records, "the settings-file base URL won over the gateway"


@pytest.mark.skipif(shutil.which("codex") is None, reason="codex is not installed")
def test_codex_routes_through_gateway(upstream, tmp_path):
    write_user_config(tmp_path / "config", upstream.url, "public", PASSTHROUGH)
    work = tmp_path / "work"
    work.mkdir()
    proc = run_launcher("codex", ["exec", "reply with the word ok"], agent_env(tmp_path, None, None), work)
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]
    assert any(r.path.startswith("/v1/responses") for r in upstream.records)


@pytest.mark.skipif(shutil.which("codex") is None, reason="codex is not installed")
def test_codex_chatgpt_session_behavior(upstream, tmp_path):
    """Record whether the custom provider bypasses a stored ChatGPT login.

    If the launch is refused, the Task 15 refusal stands. If it runs and the fake upstream
    receives the request, the provider did not bypass the session and the refusal should be
    relaxed to a warning (spec 13).
    """
    write_user_config(tmp_path / "config", upstream.url, "public", PASSTHROUGH)
    work = tmp_path / "work"
    work.mkdir()
    proc = run_launcher("codex", ["exec", "reply with the word ok"], agent_env(tmp_path, None, None), work)
    out = proc.stdout + proc.stderr
    print("exit", proc.returncode, "reached lane:", bool(upstream.records))
    print(out[-1500:])
    refused = proc.returncode != 0 and "ChatGPT login" in out and not upstream.records
    reached = any(r.path.startswith("/v1/responses") for r in upstream.records)
    assert refused or reached, "neither a launcher refusal nor a request on the lane"
