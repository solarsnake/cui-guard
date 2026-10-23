"""The human channel: notifications, typed justification and OS authentication.

Only a human at the console can grant an override. The agent never sees these prompts.
"""

from __future__ import annotations

import contextlib
import html
import shutil
import subprocess
import sys
import threading
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from cui_guard.model import DetClass

if TYPE_CHECKING:
    from cui_guard.pipeline import BlockInfo

MESSAGE_KEYS = (
    "warn.cui_public",
    "warn.controlled_public",
    "warn.generic",
    "stop.classified",
    "blocked.no_override",
)
MIN_JUSTIFICATION = 20
MAX_ATTEMPTS = 3
AUTH_TIMEOUT_S = 120
DIALOG_TIMEOUT_S = 600
LA_POLICY_DEVICE_OWNER_AUTHENTICATION = 2  # Touch ID with password fallback

_BUILTIN = Path(__file__).with_name("messages.toml")


def _flatten(data: dict[str, Any], prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in data.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_flatten(value, name + "."))
        elif isinstance(value, str):
            out[name] = value.strip()
        else:
            raise TypeError(f"message {name!r} must be a string")
    return out


def load_messages(path: str | None) -> dict[str, str]:
    """Built-in messages, with any keys defined by the org file replaced."""
    messages = _flatten(tomllib.loads(_BUILTIN.read_text(encoding="utf-8")))
    if path:
        org = _flatten(tomllib.loads(Path(path).read_text(encoding="utf-8")))
        messages.update(org)
    return messages


def render(message: str, poc: str | None) -> str:
    """Fill in {poc}; with no point of contact, drop the lines that mention it."""
    if poc:
        return message.replace("{poc}", poc)
    return "\n".join(ln for ln in message.splitlines() if "{poc}" not in ln)


def warning_key(block: BlockInfo) -> str:
    if block.cls == DetClass.CLASSIFIED_MARKING:
        return "stop.classified"
    if block.cls == DetClass.CUI_MARKING:
        return "warn.cui_public"
    if block.cls == DetClass.CONTROLLED_CONTENT:
        return "warn.controlled_public"
    return "warn.generic"


class HumanChannel(Protocol):
    def notify_block(self, block: BlockInfo, offer_override: bool) -> None: ...

    def request_justification(self, block: BlockInfo, warning: str) -> str | None: ...

    def authenticate(self, reason: str) -> bool: ...


def _notice_text(block: BlockInfo, offer_override: bool, messages: dict[str, str], poc: str | None) -> str:
    if block.cls == DetClass.CLASSIFIED_MARKING:
        return " ".join(render(messages["stop.classified"], poc).split())
    text = f"Blocked {block.rule_id} at {block.location}."
    if offer_override:
        text += f" Override requested (ID {block.override_id})."
    else:
        text += " " + " ".join(render(messages["blocked.no_override"], poc).split())
    return text


def _dialog_body(block: BlockInfo, warning: str, note: str = "") -> str:
    head = note + "\n\n" if note else ""
    return (
        f"{head}{warning}\n\n"
        f"Rule: {block.rule_id} ({block.cls.value}) at {block.location}\n"
        f"Excerpt: {block.excerpt}\n"
        f"Override ID: {block.override_id}\n\n"
        f"Type a justification of at least {MIN_JUSTIFICATION} characters."
    )


class _Base:
    def __init__(self, messages: dict[str, str] | None = None, poc: str | None = None) -> None:
        self.messages = messages if messages is not None else load_messages(None)
        self.poc = poc

    def _show(self, text: str) -> None:
        raise NotImplementedError

    def _ask(self, body: str) -> str | None:
        raise NotImplementedError

    def notify_block(self, block: BlockInfo, offer_override: bool) -> None:
        self._show(_notice_text(block, offer_override, self.messages, self.poc))

    def request_justification(self, block: BlockInfo, warning: str) -> str | None:
        note = ""
        for _ in range(MAX_ATTEMPTS):
            answer = self._ask(_dialog_body(block, warning, note))
            if answer is None:
                return None
            answer = answer.strip()
            if len(answer) >= MIN_JUSTIFICATION:
                return answer
            note = f"Justification too short: at least {MIN_JUSTIFICATION} characters are required."
        return None


_MAC_NOTIFY = [
    "on run argv",
    'display notification (item 1 of argv) with title "cui-guard"',
    "end run",
]
_MAC_DIALOG = [
    "on run argv",
    (
        'set r to display dialog (item 1 of argv) default answer "" '
        'buttons {"Cancel", "Override"} default button "Override" '
        'cancel button "Cancel" with title "cui-guard override" with icon caution'
    ),
    "return text returned of r",
    "end run",
]


def _osascript(lines: list[str], text: str) -> list[str]:
    # the text travels as an argv item, never inside the script source: nothing to escape or inject
    cmd = ["osascript"]
    for ln in lines:
        cmd += ["-e", ln]
    return [*cmd, text]


class MacChannel(_Base):
    def __init__(
        self,
        messages: dict[str, str] | None = None,
        poc: str | None = None,
        context_factory: Callable[[], Any] | None = None,
    ) -> None:
        super().__init__(messages, poc)
        self._context_factory = context_factory

    def _show(self, text: str) -> None:
        subprocess.run(_osascript(_MAC_NOTIFY, text), capture_output=True, timeout=30, check=False)

    def _ask(self, body: str) -> str | None:
        try:
            proc = subprocess.run(
                _osascript(_MAC_DIALOG, body),
                capture_output=True, text=True, timeout=DIALOG_TIMEOUT_S, check=False,
            )  # fmt: skip
        except (subprocess.TimeoutExpired, OSError):
            return None
        if proc.returncode != 0:
            return None  # Cancel is a non-zero exit
        return proc.stdout.rstrip("\n")

    def _make_context(self) -> Any:
        if self._context_factory is not None:
            return self._context_factory()
        import LocalAuthentication  # lazy: optional pyobjc dependency

        return LocalAuthentication.LAContext.alloc().init()

    def authenticate(self, reason: str) -> bool:
        try:
            ctx = self._make_context()
        except ImportError:
            with contextlib.suppress(Exception):  # a failed notice never changes the outcome
                self._show(
                    "Override unavailable: pyobjc-framework-LocalAuthentication is not installed."
                )
            return False
        except Exception:  # noqa: BLE001
            return False
        try:
            done = threading.Event()
            result = [False]

            def reply(success: Any, error: Any) -> None:
                result[0] = bool(success)
                done.set()

            ctx.evaluatePolicy_localizedReason_reply_(
                LA_POLICY_DEVICE_OWNER_AUTHENTICATION, reason, reply
            )
            if not done.wait(AUTH_TIMEOUT_S):
                return False
            return result[0]
        except Exception:  # noqa: BLE001 - fail closed
            return False


class LinuxChannel(_Base):
    def _show(self, text: str) -> None:
        subprocess.run(
            ["notify-send", "cui-guard", text], capture_output=True, timeout=30, check=False
        )

    def _ask(self, body: str) -> str | None:
        if shutil.which("zenity") or not shutil.which("kdialog"):
            cmd = [
                "zenity", "--entry", "--title=cui-guard override",
                "--text=" + html.escape(body), "--width=600",
            ]  # fmt: skip
        else:
            cmd = ["kdialog", "--title", "cui-guard override", "--inputbox", html.escape(body)]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=DIALOG_TIMEOUT_S, check=False
            )
        except (subprocess.TimeoutExpired, OSError):
            return None
        if proc.returncode != 0:
            return None
        return proc.stdout.rstrip("\n")

    def authenticate(self, reason: str) -> bool:
        try:
            proc = subprocess.run(
                ["pkexec", "/bin/true"], capture_output=True, timeout=AUTH_TIMEOUT_S, check=False
            )
        except (subprocess.TimeoutExpired, OSError):
            return False
        return proc.returncode == 0


class HeadlessChannel:
    def __init__(self, messages: dict[str, str] | None = None, poc: str | None = None) -> None:
        self.messages = messages if messages is not None else load_messages(None)
        self.poc = poc

    def notify_block(self, block: BlockInfo, offer_override: bool) -> None:
        text = _notice_text(block, False, self.messages, self.poc)
        sys.stderr.write(f"cui-guard: {text}\n")
        sys.stderr.flush()

    def request_justification(self, block: BlockInfo, warning: str) -> str | None:
        return None

    def authenticate(self, reason: str) -> bool:
        return False


class FakeChannel:
    """Test double: records every call and answers with canned values."""

    def __init__(self, justification: str | None, auth_ok: bool) -> None:
        self.justification = justification
        self.auth_ok = auth_ok
        self.notifications: list[tuple[BlockInfo, bool]] = []
        self.justification_requests: list[tuple[BlockInfo, str]] = []
        self.auth_requests: list[str] = []

    def notify_block(self, block: BlockInfo, offer_override: bool) -> None:
        self.notifications.append((block, offer_override))

    def request_justification(self, block: BlockInfo, warning: str) -> str | None:
        self.justification_requests.append((block, warning))
        return self.justification

    def authenticate(self, reason: str) -> bool:
        self.auth_requests.append(reason)
        return self.auth_ok


def select_channel(
    headless: bool, messages: dict[str, str] | None = None, poc: str | None = None
) -> HumanChannel:
    if headless:
        return HeadlessChannel(messages, poc)
    if sys.platform == "darwin":
        return MacChannel(messages, poc)
    if sys.platform.startswith("linux"):
        return LinuxChannel(messages, poc)
    return HeadlessChannel(messages, poc)
