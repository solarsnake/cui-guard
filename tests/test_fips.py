from __future__ import annotations

import os
import platform
import shutil
import ssl
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from cui_guard import cli
from cui_guard import fips as fips_mod
from cui_guard.fips import (
    FipsCheck,
    FipsError,
    Probes,
    fips_status,
    python_support,
    require_fips,
    upstream_ssl_context,
)
from cui_guard.gateway.app import GatewayConfig
from cui_guard.model import Trust
from cui_guard.policy.loader import load_builtin_layer
from cui_guard.policy.merge import merge_layers
from cui_guard.policy.schema import AuditConfig, Endpoint, PolicyError, parse_layer
from cui_guard.policy.snapshot import loosenings

TEST_CA = Path(__file__).parent / "fixtures" / "test-ca.crt"
NAMES = ["os", "openssl-fips-provider", "hashlib-openssl", "kernel-fips"]


def probes(os_name="Linux", provider=True, hashlib_ok=True, kernel=True) -> Probes:
    return Probes(
        os_name=lambda: os_name,
        openssl_fips_provider=lambda: provider,
        hashlib_openssl=lambda: hashlib_ok,
        kernel_fips=lambda: kernel,
    )


def test_all_checks_pass_with_fips_probes():
    checks = fips_status(probes())
    assert [c.name for c in checks] == NAMES
    assert all(isinstance(c, FipsCheck) and c.ok for c in checks)
    require_fips(probes())


def test_macos_fails_os_check():
    checks = fips_status(probes(os_name="Darwin"))
    assert checks[0].name == "os" and not checks[0].ok
    assert all(c.ok for c in checks[1:])
    with pytest.raises(FipsError) as e:
        require_fips(probes(os_name="Darwin"))
    assert "os" in str(e.value)


def test_hacl_fallback_detected():
    checks = {c.name: c for c in fips_status(probes(hashlib_ok=False))}
    assert not checks["hashlib-openssl"].ok
    assert [n for n, c in checks.items() if not c.ok] == ["hashlib-openssl"]


def test_kernel_flag_missing_fails():
    checks = {c.name: c for c in fips_status(probes(kernel=False))}
    assert [n for n, c in checks.items() if not c.ok] == ["kernel-fips"]


def test_require_fips_lists_every_failure():
    with pytest.raises(FipsError) as e:
        require_fips(probes(provider=False, kernel=False))
    lines = str(e.value).splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("openssl-fips-provider")
    assert lines[1].startswith("kernel-fips")


def test_probe_exception_fails_closed():
    def boom() -> bool:
        raise OSError("probe broke")

    bad = Probes(lambda: "Linux", boom, lambda: True, lambda: True)
    checks = {c.name: c for c in fips_status(bad)}
    assert not checks["openssl-fips-provider"].ok


@pytest.mark.parametrize(
    ("content", "expected"), [("1\n", True), ("0\n", False), ("", False), (None, False)]
)
def test_kernel_probe_reads_the_flag(tmp_path, monkeypatch, content, expected):
    flag = tmp_path / "fips_enabled"
    if content is not None:
        flag.write_text(content)
    monkeypatch.setattr(fips_mod, "KERNEL_FIPS_FLAG", flag)
    assert fips_mod.probe_kernel_fips() is expected


def test_hashlib_probe_detects_builtin_sha256(monkeypatch):
    import hashlib

    _sha2 = pytest.importorskip("_sha2", reason="this Python has no built-in SHA-2")
    assert fips_mod.probe_hashlib_openssl() is True
    monkeypatch.setattr(hashlib, "sha256", _sha2.sha256)
    assert fips_mod.probe_hashlib_openssl() is False


def test_real_provider_probe_fails_off_a_fips_host():
    # No kernel FIPS flag and no OPENSSL_CONF: nothing can have turned the provider on.
    if fips_mod.probe_kernel_fips() or os.environ.get("OPENSSL_CONF"):
        pytest.skip("host may legitimately run the FIPS provider")
    assert fips_mod.probe_openssl_fips_provider() is False


def test_host_probes_run_without_error():
    # The real probes on whatever host runs the suite: four checks, and never "ok" for
    # the OS check off Linux.
    checks = fips_status()
    assert [c.name for c in checks] == NAMES
    if sys.platform != "linux":
        assert not checks[0].ok


def test_tls_floor_always_set():
    ctx = upstream_ssl_context(None, False)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def _bundle_count(path: str) -> int:
    return Path(path).read_text(encoding="ascii").count("-----" + "BEGIN CERTIFICATE")


def test_default_store_is_certifi_outside_fips_mode():
    import certifi

    ctx = upstream_ssl_context(None, False)
    assert len(ctx.get_ca_certs()) == _bundle_count(certifi.where())


def _expected_platform_store() -> dict[str, str]:
    paths = ssl.get_default_verify_paths()
    out = {}
    if paths.openssl_cafile and os.path.isfile(paths.openssl_cafile):
        out["cafile"] = paths.openssl_cafile
    if paths.openssl_capath and os.path.isdir(paths.openssl_capath):
        out["capath"] = paths.openssl_capath
    return out


def test_fips_mode_uses_platform_store_not_certifi(monkeypatch):
    import certifi

    expected = _expected_platform_store()
    if not expected:
        pytest.skip("this OpenSSL has no compiled-in default store")
    calls = []
    real = ssl.create_default_context

    def spy(*args, **kwargs):
        calls.append(kwargs)
        return real(*args, **kwargs)

    def no_certifi() -> str:
        raise AssertionError("certifi used in FIPS mode")

    monkeypatch.setattr(ssl, "create_default_context", spy)
    monkeypatch.setattr(certifi, "where", no_certifi)
    ctx = upstream_ssl_context(None, True)
    assert calls == [expected]  # OpenSSL's compiled-in paths, passed explicitly
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2 and ctx.check_hostname


@pytest.mark.parametrize("fips", [False, True])
def test_ssl_cert_env_cannot_change_trust_roots(tmp_path, monkeypatch, fips):
    if fips and not _expected_platform_store():
        pytest.skip("this OpenSSL has no compiled-in default store")
    ca = _private_copy(tmp_path)
    certdir = tmp_path / "certdir"
    certdir.mkdir()
    shutil.copyfile(ca, certdir / "injected.crt")
    monkeypatch.setenv("SSL_CERT_FILE", str(ca))
    monkeypatch.setenv("SSL_CERT_DIR", str(certdir))
    ctx = upstream_ssl_context(None, fips)
    names = [
        dict(x[0] for x in c["subject"]).get("commonName") for c in ctx.get_ca_certs()
    ]
    assert "cui-guard synthetic test CA" not in names


def test_fips_mode_without_platform_store_refused(tmp_path, monkeypatch):
    missing = ssl.DefaultVerifyPaths(
        None,
        None,
        "SSL_CERT_FILE",
        str(tmp_path / "no.crt"),
        "SSL_CERT_DIR",
        str(tmp_path / "no"),
    )
    monkeypatch.setattr(ssl, "get_default_verify_paths", lambda: missing)
    with pytest.raises(PolicyError, match="no system trust store"):
        upstream_ssl_context(None, True)


def test_fips_context_restricts_ciphers():
    ctx = upstream_ssl_context(None, True)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    tls12 = [c["name"] for c in ctx.get_ciphers() if c["protocol"] == "TLSv1.2"]
    assert tls12
    for name in tls12:
        assert "GCM" in name and name.startswith("ECDHE"), name


def _private_copy(tmp_path: Path) -> Path:
    path = tmp_path / "ca-bundle.crt"
    shutil.copyfile(TEST_CA, path)
    path.chmod(0o644)
    return path


@pytest.mark.parametrize("fips", [False, True])
def test_ca_file_replaces_default_store(tmp_path, fips):
    ctx = upstream_ssl_context(str(_private_copy(tmp_path)), fips)
    certs = ctx.get_ca_certs()
    assert len(certs) == 1
    subject = dict(x[0] for x in certs[0]["subject"])
    assert subject["commonName"] == "cui-guard synthetic test CA"
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.check_hostname is True


@pytest.mark.parametrize("mode", [0o666, 0o664, 0o646])
def test_ca_file_world_writable_refused(tmp_path, mode):
    path = _private_copy(tmp_path)
    path.chmod(mode)
    with pytest.raises(PolicyError, match="writable"):
        upstream_ssl_context(str(path), False)


def test_ca_file_relative_path_refused(tmp_path, monkeypatch):
    _private_copy(tmp_path)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(PolicyError, match="absolute"):
        upstream_ssl_context("ca-bundle.crt", False)


def test_ca_file_symlink_target_is_checked(tmp_path):
    target = _private_copy(tmp_path)
    link = tmp_path / "link.crt"
    link.symlink_to(target)
    assert len(upstream_ssl_context(str(link), False).get_ca_certs()) == 1
    target.chmod(0o666)
    with pytest.raises(PolicyError, match="writable"):
        upstream_ssl_context(str(link), False)


def test_ca_file_not_a_bundle_refused(tmp_path):
    for name, data in (
        ("binary.crt", bytes(range(256))),
        ("empty.crt", b"no certs here\n"),
    ):
        path = tmp_path / name
        path.write_bytes(data)
        path.chmod(0o644)
        with pytest.raises(PolicyError, match="ca_file"):
            upstream_ssl_context(str(path), False)
    with pytest.raises(PolicyError, match="regular file"):
        upstream_ssl_context(str(tmp_path), False)


def test_ca_file_missing_refused(tmp_path):
    with pytest.raises(PolicyError):
        upstream_ssl_context(str(tmp_path / "absent.crt"), False)


def test_ca_file_foreign_owner_refused(tmp_path, monkeypatch):
    path = _private_copy(tmp_path)
    monkeypatch.setattr(os, "getuid", lambda: os.stat(path).st_uid + 4242)
    if os.stat(path).st_uid == 0:
        pytest.skip("running as root: root-owned files are always accepted")
    with pytest.raises(PolicyError, match="owned"):
        upstream_ssl_context(str(path), False)


def test_python_support_table():
    today = date(2026, 10, 27)
    assert python_support((3, 11), today) == "supported"
    assert python_support((3, 10), today) == "unknown"
    assert python_support((3, 11), date(2027, 11, 1)) == "end-of-life"
    assert python_support((3, 15, 0, "final", 0), today) == "supported"


def test_fips_policy_merge_is_strictest():
    builtin = load_builtin_layer()
    assert builtin.fips == "off"
    assert merge_layers(builtin, None, None).fips == "off"
    org = parse_layer({"fips": "require"}, "org")
    user_off = parse_layer({"fips": "off"}, "user")
    merged = merge_layers(builtin, user_off, org)
    assert merged.fips == "require"
    assert merged.provenance["fips"] == "org"
    user_req = parse_layer({"fips": "require"}, "user")
    assert merge_layers(builtin, user_req, None).fips == "require"
    with pytest.raises(PolicyError):
        parse_layer({"fips": "on"}, "user")


def test_user_fips_require_is_a_tightening():
    assert loosenings(None, parse_layer({"fips": "require"}, "user")) == []


def test_ca_file_change_is_a_loosening():
    raw = {
        "endpoints": {
            "corp": {
                "url": "https://llm.corp.example.invalid",
                "formats": ["anthropic"],
                "ca_file": "/etc/pki/corp-roots.crt",
            }
        }
    }
    layer = parse_layer(raw, "user")
    assert layer.endpoints["corp"].ca_file == "/etc/pki/corp-roots.crt"
    reasons = loosenings(None, layer)
    assert "endpoint corp trust store changed (ca_file)" in reasons
    assert "endpoint corp trust store changed (ca_file)" not in loosenings(layer, layer)


def _fips_cfg(tmp_path) -> GatewayConfig:
    policy = merge_layers(load_builtin_layer(), None, None)
    policy.audit = AuditConfig(path=str(tmp_path / "audit.jsonl"))
    policy.fips = "require"
    lane = Endpoint("local", "http://127.0.0.1:9", ("anthropic",), Trust.LOCAL, "none")
    return GatewayConfig("t" * 32, "claude", lane, policy, "none", None, True, "sess")


def test_gateway_refuses_start_when_fips_required_and_unavailable(tmp_path):
    flag = Path("/proc/sys/crypto/fips_enabled")
    kernel_on = flag.exists() and flag.read_text().strip() == "1"
    failed = []  # derived from the host, not from fips_status()
    if platform.system() != "Linux":
        failed.append("os")
    if not kernel_on:
        failed.append("kernel-fips")
    if not kernel_on and not os.environ.get("OPENSSL_CONF"):
        failed.append("openssl-fips-provider")
    if not failed:
        pytest.skip("this host may pass every FIPS check")
    cfg = _fips_cfg(tmp_path)
    proc = subprocess.run(
        [sys.executable, "-m", "cui_guard.gateway"],
        input=cfg.to_json() + "\n",
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode != 0
    assert "READY" not in proc.stdout  # never reached the point of listening
    for name in failed:  # on macOS: os, openssl-fips-provider and kernel-fips
        assert f"{name}:" in proc.stderr, name
    assert "Traceback" not in proc.stderr
    assert not (tmp_path / "audit.jsonl").exists()


def test_gateway_config_roundtrips_ca_file_and_fips(tmp_path):
    cfg = _fips_cfg(tmp_path)
    cfg.lane = Endpoint(
        "corp", "https://llm.corp.example.invalid", ("anthropic",), Trust.APPROVED,
        "none", "/etc/pki/corp-roots.crt",
    )  # fmt: skip
    again = GatewayConfig.from_json(cfg.to_json())
    assert again.lane == cfg.lane
    assert again.policy.fips == "require"


def test_doctor_output(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(
        "cui_guard.policy.loader.org_policy_path", lambda: tmp_path / "no-org.toml"
    )
    canary = "sk-" + "ant-" + "doctorcanary" + "0" * 24
    monkeypatch.setenv("ANTHROPIC_API_KEY", canary)
    monkeypatch.setenv("OPENAI_API_KEY", canary)
    monkeypatch.setattr(
        cli, "fips_status", lambda: fips_status(probes(os_name="Darwin"))
    )
    assert cli.main(["doctor"]) == 0
    out = capsys.readouterr().out
    lines = out.splitlines()
    ver = ".".join(str(p) for p in sys.version_info[:3])
    assert lines[0].startswith(f"python {ver} (")
    assert lines[1] == f"openssl {ssl.OPENSSL_VERSION}"
    assert lines[2].startswith("os FAIL")
    for name in NAMES[1:]:
        assert any(ln.startswith(f"{name} ok") for ln in lines), name
    assert "tls minimum TLSv1_2" in lines
    assert "policy fips=off" in lines
    assert canary not in out and "doctorcanary" not in out
    assert cli.main(["doctor", "--require-fips"]) == 1
    monkeypatch.setattr(cli, "fips_status", lambda: fips_status(probes()))
    assert cli.main(["doctor", "--require-fips"]) == 0
