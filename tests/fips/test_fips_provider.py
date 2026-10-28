"""FIPS provider checks against a real OpenSSL FIPS provider (design 8.3).

These run only inside the Red Hat UBI 9 container started by tests/fips/run_in_ubi9.sh,
which forces the provider on through OPENSSL_CONF and sets CUI_GUARD_FIPS_CONTAINER=1.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from cui_guard.fips import fips_status, upstream_ssl_context

pytestmark = pytest.mark.skipif(
    os.environ.get("CUI_GUARD_FIPS_CONTAINER") != "1",
    reason="runs only in the UBI 9 FIPS container (scripts/check fips)",
)


def test_provider_checks_pass_in_container():
    checks = {c.name: c for c in fips_status()}
    assert checks["os"].ok, checks["os"].detail
    assert checks["openssl-fips-provider"].ok, checks["openssl-fips-provider"].detail
    assert checks["hashlib-openssl"].ok, checks["hashlib-openssl"].detail


def test_md5_blocked():
    # Sanity that FIPS is really on. OpenSSL itself refuses MD5, and hashlib has no
    # fallback to a built-in copy. Red Hat's Python leaves hashlib.md5 undefined in FIPS
    # mode; where it is defined, calling it must fail.
    import _hashlib

    with pytest.raises(ValueError):
        _hashlib.new("md5")
    with pytest.raises(ValueError):
        hashlib.new("md5")  # noqa: S324 - must be refused
    md5 = getattr(hashlib, "md5", None)
    if md5 is not None:
        with pytest.raises(ValueError):
            md5()


def _openssl(*args: str, cwd: Path) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def _make_ca_and_leaf(d: Path) -> tuple[Path, Path, Path]:
    """A throwaway CA and a localhost leaf. Private keys exist only in tmp_path."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl CLI not available")
    ec = ("-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc")
    _openssl(
        "req", "-x509", *ec, "-keyout", "ca.priv", "-out", "ca.crt", "-days", "2",
        "-subj", "/CN=cui-guard synthetic handshake CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        cwd=d,
    )  # fmt: skip
    _openssl(
        "req", *ec, "-keyout", "leaf.priv", "-out", "leaf.csr",
        "-subj", "/CN=localhost", cwd=d,
    )  # fmt: skip
    (d / "leaf.ext").write_text(
        "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"
        "authorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n"
    )
    _openssl(
        "x509", "-req", "-in", "leaf.csr", "-CA", "ca.crt", "-CAkey", "ca.priv",
        "-CAcreateserial", "-out", "leaf.crt", "-days", "2", "-extfile", "leaf.ext",
        cwd=d,
    )  # fmt: skip
    ca = d / "ca.crt"
    ca.chmod(0o644)
    return ca, d / "leaf.crt", d / "leaf.priv"


@pytest.mark.parametrize("server_max", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
def test_tls_handshake_with_fips_context(tmp_path, server_max):
    ca, leaf, key = _make_ca_and_leaf(tmp_path)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.maximum_version = server_max
    server_ctx.load_cert_chain(leaf, key)
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            conn, _ = listener.accept()
            with server_ctx.wrap_socket(conn, server_side=True) as tls:
                tls.sendall(b"ok")
        except BaseException as e:  # noqa: BLE001 - reported by the main thread
            errors.append(e)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    client_ctx = upstream_ssl_context(str(ca), True)
    try:
        with (
            socket.create_connection(("127.0.0.1", port), timeout=10) as raw,
            client_ctx.wrap_socket(raw, server_hostname="localhost") as tls,
        ):
            assert tls.recv(2) == b"ok"
            cipher, version, _ = tls.cipher()
    finally:
        t.join(timeout=10)
        listener.close()
    assert not errors, errors
    assert "GCM" in cipher
    if server_max == ssl.TLSVersion.TLSv1_2:
        assert version == "TLSv1.2" and cipher.startswith("ECDHE"), cipher
