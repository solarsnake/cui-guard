"""The `cui-guard` command."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from cui_guard import __version__
from cui_guard.detect.engine import Detector
from cui_guard.detect.ner import load_presidio
from cui_guard.detect.rules import load_builtin_rules
from cui_guard.launch.claude import run_claude
from cui_guard.launch.codex import run_codex
from cui_guard.launch.generic import run_generic
from cui_guard.launch.session import LaunchError
from cui_guard.model import Action
from cui_guard.orgemit import emit_claude_managed_settings, emit_codex_requirements
from cui_guard.policy.loader import load_effective_policy, state_dir
from cui_guard.policy.schema import EffectivePolicy, PolicyError

NER_MODEL = "en_core_web_sm"


def _split_dashdash(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1 :]
    return argv, []


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cui-guard", description=__doc__)
    p.add_argument("--version", action="version", version=f"cui-guard {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    for name in ("claude", "codex"):
        sp = sub.add_parser(name, help=f"launch {name} through the gateway")
        sp.add_argument("--lane")
        sp.add_argument("--headless", action="store_true")
        sp.add_argument("--profile", help="session-only tightening; only 'cui' is accepted")
    sp = sub.add_parser("run", help="run any command through the gateway")
    sp.add_argument("--lane")
    sp.add_argument("--headless", action="store_true")
    sp.add_argument("--profile", help="session-only tightening; only 'cui' is accepted")

    sp = sub.add_parser("scan", help="scan a file or stdin; prints no matched values")
    sp.add_argument("file", nargs="?", default="-")
    sp.add_argument("--lane")
    sub.add_parser("lanes", help="list configured lanes")
    sub.add_parser("status", help="list running sessions")
    sp = sub.add_parser("log", help="show recent audit records")
    sp.add_argument("-n", type=int, default=20)
    sp = sub.add_parser("policy", help="show the effective policy and where each setting came from")
    sp.add_argument("--show-identifiers", action="store_true", help="print identifier literals")
    sp = sub.add_parser("setup", help="optional setup steps")
    sp.add_argument("what", choices=["ner"])
    sp.add_argument("--yes", action="store_true")
    sp = sub.add_parser("org", help="emit organization configuration")
    sp.add_argument("action", choices=["emit"])
    sp.add_argument("target", choices=["claude-managed-settings", "codex-requirements"])
    sp.add_argument("--gateway-url", help="gateway URL for claude-managed-settings")
    return p


def _policy() -> EffectivePolicy:
    try:
        return load_effective_policy()[0]
    except PolicyError as e:
        raise LaunchError(f"policy error: {e}") from e


def _check_profile(profile: str | None) -> None:
    if profile is None:
        return
    if profile == "cui":
        print(
            "cui-guard: --profile cui is accepted; the launcher does not apply it beyond "
            "the effective policy, so it has no effect unless the policy is already cui.",
            file=sys.stderr,
        )
    else:
        print(
            f"cui-guard: warning: --profile {profile} is looser than cui and is ignored.",
            file=sys.stderr,
        )


def _cmd_scan(args: argparse.Namespace) -> int:
    policy = _policy()
    lane_name = args.lane or policy.default_lane or "anthropic"
    lane = policy.endpoints.get(lane_name)
    if lane is None:
        raise LaunchError(f"unknown lane {lane_name!r}; known: {sorted(policy.endpoints)}")
    if args.file == "-":
        text = sys.stdin.read()
    else:
        try:
            text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise LaunchError(f"cannot read {args.file}: {e}") from e
    detector = Detector(load_builtin_rules() + policy.extra_rules, policy.identifiers, load_presidio())
    blocked = False
    for hit in sorted(detector.scan(text), key=lambda h: h.start):
        action = policy.action_for(hit, lane.trust)
        blocked = blocked or action >= Action.BLOCK
        line = text.count("\n", 0, hit.start) + 1
        col = hit.start - (text.rfind("\n", 0, hit.start) + 1) + 1
        rid = hit.rule_id + ("" if hit.verified else " (unverified)")
        name = {Action.BLOCK_HARD: "block-hard"}.get(action, action.name.lower())
        print(f"{rid} {hit.cls.value} {line}:{col} {name}")
    return 1 if blocked else 0


def _cmd_lanes() -> int:
    policy = _policy()
    for name in sorted(policy.endpoints):
        ep = policy.endpoints[name]
        print(f"{name}  {ep.url}  {','.join(ep.formats)}  {ep.trust.value}  {ep.credential}")
    return 0


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _cmd_status() -> int:
    files = sorted((state_dir() / "sessions").glob("*.json"))
    live = 0
    for f in files:
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            pid = int(d["pid"])
        except (OSError, ValueError, KeyError, TypeError):
            print(f"{f.stem}  unreadable (stale)")
            continue
        if not _pid_alive(pid):
            print(f"{f.stem}  pid {pid} not running (stale)")
            continue
        live += 1
        print(
            f"{f.stem}  pid={pid} port={d.get('port')} agent={d.get('agent')} "
            f"lane={d.get('lane')} trust={d.get('trust')} started={d.get('started')}"
        )
    if live == 0:
        print("no running sessions")
    return 0


def _cmd_log(n: int) -> int:
    policy = _policy()
    path = Path(os.path.expanduser(policy.audit.path))
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        print(f"no audit log at {path}")
        return 0
    except OSError as e:
        raise LaunchError(f"cannot read audit log {path}: {e}") from e
    recent = [ln for ln in lines if ln.strip()]
    recent = recent[-n:] if n > 0 else []
    bad = 0
    for ln in recent:
        try:
            r = json.loads(ln)
            hits = r.get("hits") or {}
            total = sum(hits.values()) if isinstance(hits, dict) else 0
            rules = ",".join(str(x) for x in r.get("blocked_rules") or []) or "-"
            print(f"{r['ts']} {r['agent']} {r['lane']} {r['action']} {rules} {total}")
        except (ValueError, KeyError, TypeError, AttributeError):
            bad += 1
    if bad:
        print(f"({bad} unparseable line(s) skipped)")
    return 0


def _cmd_policy(show_identifiers: bool) -> int:
    policy = _policy()
    d = policy.to_dict()
    if not show_identifiers:
        d["identifiers"] = {k: len(v) for k, v in d["identifiers"].items()}
        kinds = tuple(f"identifiers.{k}." for k in d["identifiers"])
        prov: dict[str, str] = {}
        for k, v in d["provenance"].items():
            kind = next((p for p in kinds if k.startswith(p)), None)
            prov[kind + "*" if kind else k] = v
        d["provenance"] = prov
    d["extra_rules"] = [
        {"id": r["id"], "class": r.get("class"), "source": r.get("source")}
        if isinstance(r, dict)
        else str(r)
        for r in d["extra_rules"]
    ]
    print(json.dumps(d, indent=2, sort_keys=True, default=str))
    return 0


def _cmd_setup_ner(yes: bool) -> int:
    try:
        import spacy  # noqa: F401
    except ImportError:
        print(
            "spaCy is not installed. Install the optional extras first:\n"
            "  pipx install 'cui-guard[ner]'\n"
            "or, for an existing install:\n"
            "  pipx inject cui-guard presidio-analyzer spacy",
            file=sys.stderr,
        )
        return 1
    cmd = [sys.executable, "-m", "spacy", "download", NER_MODEL]
    print(f"This will download the spaCy model {NER_MODEL} from the network by running:")
    print("  " + " ".join(cmd))
    print("This is the only cui-guard command that fetches anything from the network.")
    if not yes:
        try:
            answer = input("Type 'yes' to continue: ")
        except EOFError:
            answer = ""
        if answer.strip().lower() != "yes":
            print("Cancelled.")
            return 1
    return subprocess.run(cmd, check=False).returncode  # noqa: S603 -- argv list, no shell; cmd is the gateway-built command


def _cmd_org(args: argparse.Namespace) -> int:
    if args.target == "claude-managed-settings":
        if not args.gateway_url:
            raise LaunchError("claude-managed-settings needs --gateway-url")
        print(json.dumps(emit_claude_managed_settings(args.gateway_url), indent=2))
    else:
        print(emit_codex_requirements(), end="")
    return 0


def _dispatch(argv: list[str]) -> int:
    head, rest = _split_dashdash(argv)
    args = _build_parser().parse_args(head)
    cmd = args.command
    if cmd in ("claude", "codex", "run"):
        _check_profile(args.profile)
        if cmd == "run":
            if not rest:
                raise LaunchError("run needs a command after --")
            return run_generic(rest, args.lane, args.headless)
        runner = run_claude if cmd == "claude" else run_codex
        return runner(rest, args.lane, args.headless)
    if rest:
        _build_parser().error("unexpected arguments after --")
    if cmd == "scan":
        return _cmd_scan(args)
    if cmd == "lanes":
        return _cmd_lanes()
    if cmd == "status":
        return _cmd_status()
    if cmd == "log":
        return _cmd_log(args.n)
    if cmd == "policy":
        return _cmd_policy(args.show_identifiers)
    if cmd == "setup":
        return _cmd_setup_ner(args.yes)
    return _cmd_org(args)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        return _dispatch(argv)
    except LaunchError as e:
        print(f"cui-guard: {e}", file=sys.stderr)
        return 2
    except SystemExit as e:  # argparse errors and --version
        code = e.code
        return code if isinstance(code, int) else (0 if code is None else 2)


if __name__ == "__main__":
    sys.exit(main())
