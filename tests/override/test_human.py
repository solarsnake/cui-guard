import subprocess
import sys

import pytest

from cui_guard.model import Action, DetClass
from cui_guard.override import human
from cui_guard.override.human import (
    FakeChannel,
    HeadlessChannel,
    LinuxChannel,
    MacChannel,
    load_messages,
    render,
    select_channel,
)
from cui_guard.pipeline import BlockInfo

BLOCK = BlockInfo("cui.marking", DetClass.CUI_MARKING, Action.BLOCK, "messages[0]", "x [CUI]", "h" * 64, "abc")
LONG = "approved test data, not CUI, per my review"


def test_messages_contain_required_citations():
    m = load_messages(None)
    assert set(m) >= set(human.MESSAGE_KEYS)
    cui = m["warn.cui_public"]
    assert "ISOO Notice 2026-01" in cui and "DFARS 252.204-7012" in cui and "72" in cui
    assert "federal personnel under ISOO Notice 2026-01" in cui and "FedRAMP" in cui
    assert "not CUI" in cui and "consequences" in cui
    stop = m["stop.classified"]
    assert "spill" in stop and "security officer" in stop and "Nothing was forwarded" in stop


def test_org_messages_override(tmp_path):
    f = tmp_path / "m.toml"
    f.write_text('[warn]\ngeneric = "Org text {poc}"\n', encoding="utf-8")
    m = load_messages(str(f))
    assert m["warn.generic"] == "Org text {poc}"
    assert "ISOO Notice 2026-01" in m["warn.cui_public"]  # undefined keys stay built-in


def test_poc_rendering():
    m = load_messages(None)
    assert "ISSO x1234" in render(m["blocked.no_override"], "ISSO x1234")
    bare = render(m["blocked.no_override"], None)
    assert "{poc}" not in bare and "contact" not in bare and "No override available." in bare


def test_headless_never_grants(capsys):
    ch = HeadlessChannel()
    ch.notify_block(BLOCK, True)
    assert "cui.marking" in capsys.readouterr().err
    assert ch.request_justification(BLOCK, "w") is None
    assert ch.authenticate("r") is False


def test_select_channel_platform(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    assert isinstance(select_channel(False), MacChannel)
    monkeypatch.setattr(sys, "platform", "linux")
    assert isinstance(select_channel(False), LinuxChannel)
    assert isinstance(select_channel(True), HeadlessChannel)
    monkeypatch.setattr(sys, "platform", "win32")
    assert isinstance(select_channel(False), HeadlessChannel)


def test_fake_channel_records():
    ch = FakeChannel(LONG, True)
    ch.notify_block(BLOCK, True)
    assert ch.request_justification(BLOCK, "w") == LONG
    assert ch.authenticate("why") is True
    assert ch.notifications == [(BLOCK, True)] and ch.auth_requests == ["why"]


class Runner:
    def __init__(self, *results):
        self.calls = []
        self.results = list(results)

    def __call__(self, cmd, **kw):
        self.calls.append((cmd, kw))
        rc, out = self.results.pop(0) if self.results else (0, "")
        return subprocess.CompletedProcess(cmd, rc, out, "")


def test_mac_dialog_uses_argv_not_script_interpolation(monkeypatch):
    run = Runner((0, LONG + "\n"))
    monkeypatch.setattr(subprocess, "run", run)
    evil = 'say "hi" \\ and `x` $(y)'
    assert MacChannel().request_justification(BLOCK, evil) == LONG
    cmd = run.calls[0][0]
    assert cmd[0] == "osascript" and isinstance(cmd, list)
    assert evil in cmd[-1]  # passed as an argv item
    assert all(evil not in part for part in cmd[:-1])  # never inside the script source
    assert any("default answer" in p and "Cancel" in p and "Override" in p for p in cmd)
    assert "shell" not in run.calls[0][1]


def test_mac_dialog_reprompts_then_gives_up(monkeypatch):
    run = Runner((0, "short"), (0, "short"), (0, "short"))
    monkeypatch.setattr(subprocess, "run", run)
    assert MacChannel().request_justification(BLOCK, "w") is None
    assert len(run.calls) == 3


def test_mac_dialog_cancel(monkeypatch):
    monkeypatch.setattr(subprocess, "run", Runner((1, "")))
    assert MacChannel().request_justification(BLOCK, "w") is None


def test_mac_notify_command(monkeypatch):
    run = Runner()
    monkeypatch.setattr(subprocess, "run", run)
    MacChannel().notify_block(BLOCK, True)
    cmd = run.calls[0][0]
    assert cmd[0] == "osascript" and "display notification" in " ".join(cmd) and "abc" in cmd[-1]


class FakeContext:
    def __init__(self, ok=True, call_reply=True):
        self.ok, self.call_reply, self.seen = ok, call_reply, None

    def evaluatePolicy_localizedReason_reply_(self, policy, reason, reply):
        self.seen = (policy, reason)
        if self.call_reply:
            reply(self.ok, None)


def test_mac_authenticate_with_fake_context():
    ctx = FakeContext(ok=True)
    assert MacChannel(context_factory=lambda: ctx).authenticate("why") is True
    assert ctx.seen == (2, "why")
    assert MacChannel(context_factory=lambda: FakeContext(ok=False)).authenticate("w") is False


def test_mac_authenticate_timeout_and_errors(monkeypatch):
    monkeypatch.setattr(human, "AUTH_TIMEOUT_S", 0.05)
    assert MacChannel(context_factory=lambda: FakeContext(call_reply=False)).authenticate("w") is False

    def boom():
        raise RuntimeError

    assert MacChannel(context_factory=boom).authenticate("w") is False


def test_mac_authenticate_without_pyobjc(monkeypatch):
    run = Runner()
    monkeypatch.setattr(subprocess, "run", run)

    def missing():
        raise ImportError

    assert MacChannel(context_factory=missing).authenticate("w") is False
    assert "not installed" in run.calls[0][0][-1]


def test_linux_commands(monkeypatch):
    run = Runner((0, ""), (0, LONG + "\n"), (0, ""), (1, ""), (0, ""))
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(human.shutil, "which", lambda n: "/usr/bin/" + n if n == "zenity" else None)
    ch = LinuxChannel()
    ch.notify_block(BLOCK, True)
    assert run.calls[0][0][0] == "notify-send"
    assert ch.request_justification(BLOCK, "a<b") == LONG
    zen = run.calls[1][0]
    assert zen[:2] == ["zenity", "--entry"] and "a&lt;b" in zen[3]
    assert ch.authenticate("w") is True
    assert run.calls[2][0] == ["pkexec", "/bin/true"] and run.calls[2][1]["timeout"] == 120
    assert ch.authenticate("w") is False  # non-zero exit


def test_linux_kdialog_fallback_and_timeout(monkeypatch):
    run = Runner((0, LONG))
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(human.shutil, "which", lambda n: "/usr/bin/kdialog" if n == "kdialog" else None)
    assert LinuxChannel().request_justification(BLOCK, "w") == LONG
    assert run.calls[0][0][0] == "kdialog"

    def timeout(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(subprocess, "run", timeout)
    assert LinuxChannel().authenticate("w") is False


@pytest.mark.parametrize("cls", [DetClass.CLASSIFIED_MARKING])
def test_classified_notice_uses_stop_text(monkeypatch, cls):
    run = Runner()
    monkeypatch.setattr(subprocess, "run", run)
    b = BlockInfo("classified.banner", cls, Action.BLOCK_HARD, "m", "x", "h", None)
    MacChannel(poc="ISSO").notify_block(b, False)
    assert "security officer" in run.calls[0][0][-1] and "ISSO" in run.calls[0][0][-1]


def test_kdialog_body_is_escaped(monkeypatch):
    run = Runner((0, LONG))
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(human.shutil, "which", lambda n: "/usr/bin/kdialog" if n == "kdialog" else None)
    b = BlockInfo("r", DetClass.SECRET, Action.BLOCK, "loc<b>", "ex<i>&", "h", "abc")
    LinuxChannel().request_justification(b, "w<u>")
    body = run.calls[0][0][-1]
    assert "<" not in body.replace("&lt;", "") and "w&lt;u&gt;" in body and "ex&lt;i&gt;&amp;" in body
