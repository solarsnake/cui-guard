import json
import os
import stat

import pytest

from cui_guard.audit import AuditLog, AuditUnavailable
from cui_guard.model import Action, DetClass, Trust
from cui_guard.pipeline import BlockInfo, Decision
from cui_guard.policy.schema import AuditConfig

CANARY = "CANARY-host-db.example.mil"
CANARY2 = "sk-" + "ant-" + "Q" * 24


def decision():
    d = Decision(hit_counts={"cui.marking": 1})
    d.blocked.append(
        BlockInfo(
            "cui.marking", DetClass.CUI_MARKING, Action.BLOCK, "messages[0]",
            f"near {CANARY} and {CANARY2}", "h", "abc",
        )
    )  # fmt: skip
    d.replacements[0] = f"replaced {CANARY}"
    d.notes.append(f"note {CANARY2}")
    return d


def rec(log, d=None, **kw):
    log.record(
        agent="claude", lane="public", trust=Trust.PUBLIC, decision=d or decision(),
        request_hash="deadbeef", **kw,
    )  # fmt: skip


def test_record_has_no_values(tmp_path):
    path = tmp_path / "sub" / "audit.jsonl"
    log = AuditLog(AuditConfig(path=str(path)), "sess1", "ph")
    ov = {"id": "abc", "rule_id": "cui.marking", "excerpt": CANARY, "status": "offered"}
    rec(log, overrides=[ov, {"id": "def", "rule_id": "x"}], leftover_count=2)
    text = path.read_text()
    assert CANARY not in text and CANARY2 not in text
    row = json.loads(text)
    assert set(row) == {
        "ts", "session", "agent", "lane", "trust", "hits", "action", "blocked_rules",
        "override", "leftover_count", "request_hash", "guard_version", "policy_hash",
    }  # fmt: skip
    assert row["action"] == "blocked" and row["blocked_rules"] == ["cui.marking"]
    assert row["override"] == [
        {"id": "abc", "rule_id": "cui.marking", "status": "offered"},
        {"id": "def", "rule_id": "x"},
    ]
    assert row["leftover_count"] == 2 and row["trust"] == "public"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    rec(log, Decision())
    assert json.loads(path.read_text().splitlines()[1])["action"] == "forwarded"
    assert json.loads(path.read_text().splitlines()[1])["override"] == []


def test_preflight_writes_nothing_and_lines_parse(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(AuditConfig(path=str(path)), "s")
    log.preflight()
    assert path.read_text() == ""
    rec(log)
    log.preflight()
    rec(log)
    assert all(json.loads(x) for x in path.read_text().splitlines())
    assert len(path.read_text().splitlines()) == 2


def test_preflight_fails_when_unwritable(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    log = AuditLog(AuditConfig(path=str(blocker / "audit.jsonl")), "s")
    with pytest.raises(AuditUnavailable):
        log.preflight()


def test_bad_sink_scheme_rejected_at_construction(tmp_path):
    with pytest.raises(ValueError):
        AuditLog(AuditConfig(path=str(tmp_path / "a"), sink="http://x"), "s")


def test_pending_drained_to_sink_on_success(tmp_path, monkeypatch):
    sent = []
    log = AuditLog(AuditConfig(path=str(tmp_path / "a.jsonl"), sink="syslog:/x"), "s")
    monkeypatch.setattr(log, "_emit", sent.append)
    pending = tmp_path / "a.jsonl.pending"
    pending.write_text('{"old": 1}\n')
    rec(log)
    assert sent[0].startswith("{") and sent[1] == '{"old": 1}'
    assert pending.read_text() == ""


def test_buffer_on_sink_failure(tmp_path):
    path = tmp_path / "audit.jsonl"
    cfg = AuditConfig(path=str(path), sink="syslog:/nonexistent/dir/sock")
    rec(AuditLog(cfg, "s"))
    pending = tmp_path / "audit.jsonl.pending"
    assert json.loads(pending.read_text())["session"] == "s"


def test_block_on_sink_failure_raises(tmp_path):
    cfg = AuditConfig(
        path=str(tmp_path / "audit.jsonl"),
        sink="syslog:/nonexistent/dir/sock",
        on_sink_failure="block",
    )
    with pytest.raises(AuditUnavailable):
        rec(AuditLog(cfg, "s"))
