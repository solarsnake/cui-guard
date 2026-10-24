import pytest

from cui_guard.cli import main
from cui_guard.policy import loader


@pytest.fixture(autouse=True)
def isolated_dirs(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(loader, "org_policy_path", lambda: tmp_path / "no-org-policy.toml")
    return tmp_path


def test_scan_reports_without_values(tmp_path, capsys):
    canary = "AKIA" + "QWERTYUIOPASDFGH"
    f = tmp_path / "in.txt"
    f.write_text(f"first line\nkey = {canary}\n", encoding="utf-8")
    main(["scan", str(f)])
    out = capsys.readouterr().out
    assert canary not in out
    assert out.splitlines()[0].split()[2] == "2:7"


def test_scan_exit_code_block(tmp_path, capsys):
    f = tmp_path / "in.txt"
    f.write_text("CUI//SP-CTI\n", encoding="utf-8")
    assert main(["scan", str(f), "--lane", "anthropic"]) == 1
    assert "1:1" in capsys.readouterr().out
    clean = tmp_path / "clean.txt"
    clean.write_text("hello world\n", encoding="utf-8")
    assert main(["scan", str(clean)]) == 0


def test_scan_stdin(monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("CUI//SP-CTI\n"))
    assert main(["scan", "-"]) == 1


def test_lanes_lists_builtins(capsys):
    assert main(["lanes"]) == 0
    out = capsys.readouterr().out
    assert len(out.strip().splitlines()) >= 3
    assert "anthropic" in out


def test_policy_shows_provenance(capsys):
    assert main(["policy"]) == 0
    assert "provenance" in capsys.readouterr().out


def test_no_override_subcommand():
    assert main(["override"]) == 2


def test_status_marks_stale(isolated_dirs, capsys):
    d = loader.state_dir() / "sessions"
    d.mkdir(parents=True)
    (d / "abc.json").write_text('{"pid": 2147483646, "port": 1}', encoding="utf-8")
    assert main(["status"]) == 0
    assert "stale" in capsys.readouterr().out


def test_log_skips_bad_lines(isolated_dirs, capsys):
    p = loader.state_dir() / "audit.jsonl"
    p.parent.mkdir(parents=True)
    rec = (
        '{"ts":"t1","agent":"claude","lane":"anthropic","action":"blocked",'
        '"blocked_rules":["r1"],"hits":{"r1":2}}'
    )
    p.write_text(rec + "\nnot json\n", encoding="utf-8")
    assert main(["log", "-n", "5"]) == 0
    out = capsys.readouterr().out
    assert "t1 claude anthropic blocked r1 2" in out
    assert "1 unparseable" in out


def test_run_without_command_is_error(capsys):
    assert main(["run"]) == 2
    assert "cui-guard:" in capsys.readouterr().err


def test_loose_profile_warns(monkeypatch, capsys):
    monkeypatch.setattr("cui_guard.cli.run_generic", lambda cmd, lane, headless: 0)
    assert main(["run", "--profile", "loose", "--", "echo"]) == 0
    assert "ignored" in capsys.readouterr().err


def _write_user_config(isolated_dirs, body):
    p = loader.user_config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def test_policy_identifiers_counts_by_default(isolated_dirs, capsys):
    _write_user_config(isolated_dirs, '[identifiers]\ncodenames = ["ZEPHYRFALCON", "OTHERNAME"]\n')
    assert main(["policy"]) == 0
    out = capsys.readouterr().out
    assert "ZEPHYRFALCON" not in out
    assert '"codenames": 2' in out
    assert main(["policy", "--show-identifiers"]) == 0
    assert "ZEPHYRFALCON" in capsys.readouterr().out


def test_policy_never_prints_extra_rule_regex(isolated_dirs, capsys):
    regex = "zq9distinctive[0-9]{4}wx"
    _write_user_config(
        isolated_dirs,
        f'[[patterns]]\nid = "user-x"\nclass = "secret"\nregex = "{regex}"\n',
    )
    for extra in ([], ["--show-identifiers"]):
        assert main(["policy", *extra]) == 0
        out = capsys.readouterr().out
        assert "user-x" in out
        assert "zq9distinctive" not in out
