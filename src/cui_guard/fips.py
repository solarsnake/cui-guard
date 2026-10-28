"""TLS baseline for upstreams, FIPS mode checks and the Python support table (design 8.2, 8.3).

FIPS 140-3 validates cryptographic modules, not applications. FIPS mode here means
cui-guard refuses to run unless the platform's validated module is the one in use.
This is the only module in cui_guard that touches `ssl` or OpenSSL internals (see
tests/security/test_crypto_inventory.py).
"""

from __future__ import annotations

import ctypes
import hashlib
import importlib
import os
import platform
import ssl
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import certifi  # httpx's dependency; the trust store httpx used before this module

from cui_guard.policy.schema import PolicyError

# Month each CPython minor version reaches upstream end of life. `python_support` reports
# end-of-life from the first day of that month, a few weeks early rather than late.
PYTHON_EOL = {"3.11": "2027-10", "3.12": "2028-10", "3.13": "2029-10", "3.14": "2030-10", "3.15": "2031-10"}  # fmt: skip
FIPS_TLS12_CIPHERS = "ECDHE+AESGCM"
KERNEL_FIPS_FLAG = Path("/proc/sys/crypto/fips_enabled")
# SHA-256("abc"), FIPS 180-4 example: a known-answer test for the hash actually served.
_SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


class FipsError(Exception):
    """FIPS mode was required and at least one check failed. One line per failed check."""


@dataclass(frozen=True)
class FipsCheck:
    name: str
    ok: bool
    detail: str


def _libcrypto(module_name: str) -> ctypes.CDLL | None:
    """The libcrypto that an already-loaded extension module (`_ssl`, `_hashlib`) uses.

    Opening the extension's own shared object and resolving symbols through it reaches
    exactly the OpenSSL that module linked, wherever it lives (system, Homebrew, bundled).
    No library path is guessed. A statically linked or hidden OpenSSL gives None.
    """
    try:
        path = importlib.import_module(module_name).__file__
        if not path:
            return None
        lib = ctypes.CDLL(path)
        lib.EVP_default_properties_is_fips_enabled.argtypes = [ctypes.c_void_p]
        lib.EVP_default_properties_is_fips_enabled.restype = ctypes.c_int
        lib.OSSL_PROVIDER_available.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.OSSL_PROVIDER_available.restype = ctypes.c_int
    except (ImportError, OSError, AttributeError):
        return None
    return lib


def probe_openssl_fips_provider() -> bool:
    """The FIPS provider is the default for this process's OpenSSL, for TLS and hashing.

    `_hashlib.get_fips_mode()` is preferred for the default-properties check; without
    it, `EVP_default_properties_is_fips_enabled(NULL)` is called directly. Both
    `_hashlib`'s and `_ssl`'s libcrypto must then report `fips=yes` default properties
    and an active provider named "fips": properties alone only say what is requested.
    """
    try:
        hl = importlib.import_module("_hashlib")
    except ImportError:
        return False
    get_mode = getattr(hl, "get_fips_mode", None)
    if get_mode is not None and get_mode() != 1:
        return False
    for module_name in ("_hashlib", "_ssl"):
        lib = _libcrypto(module_name)
        if lib is None:
            return False
        if lib.EVP_default_properties_is_fips_enabled(None) != 1:
            return False
        if lib.OSSL_PROVIDER_available(None, b"fips") != 1:
            return False
    return True


def probe_hashlib_openssl() -> bool:
    """`hashlib.sha256` is OpenSSL's, not CPython's built-in HACL* fallback.

    hashlib binds `sha256` once at import: to `_hashlib.openssl_sha256` when OpenSSL
    serves SHA-256, otherwise to the built-in `_sha2` copy. Check the binding, the type
    of the object it returns, and a known answer.
    """
    try:
        hl = importlib.import_module("_hashlib")
    except ImportError:
        return False
    ctor = getattr(hl, "openssl_sha256", None)
    if ctor is None or hashlib.sha256 is not ctor:
        return False
    h = hashlib.sha256(b"abc")
    return type(h).__module__ == "_hashlib" and h.hexdigest() == _SHA256_ABC


def probe_kernel_fips() -> bool:
    try:
        return KERNEL_FIPS_FLAG.read_text(encoding="ascii").strip() == "1"
    except OSError:
        return False


@dataclass(frozen=True)
class Probes:
    """Host probes, injectable so tests never depend on the machine they run on."""

    os_name: Callable[[], str] = platform.system
    openssl_fips_provider: Callable[[], bool] = probe_openssl_fips_provider
    hashlib_openssl: Callable[[], bool] = probe_hashlib_openssl
    kernel_fips: Callable[[], bool] = probe_kernel_fips


def _run(
    name: str, probe: Callable[[], object], ok_detail: str, fail_detail: str
) -> FipsCheck:
    try:
        result = probe()
    except Exception as e:  # noqa: BLE001 - a probe that breaks is a failed check (fail closed)
        return FipsCheck(name, False, f"probe error ({type(e).__name__})")
    return FipsCheck(name, result is True, ok_detail if result is True else fail_detail)


def fips_status(probes: Probes | None = None) -> list[FipsCheck]:
    """The four FIPS mode checks, in order: os, openssl-fips-provider, hashlib-openssl, kernel-fips."""
    p = probes or Probes()
    try:
        os_name = p.os_name()
    except Exception as e:  # noqa: BLE001 - fail closed
        os_check = FipsCheck("os", False, f"probe error ({type(e).__name__})")
    else:
        os_check = FipsCheck(
            "os",
            os_name == "Linux",
            "Linux"
            if os_name == "Linux"
            else f"{os_name} is not supported in FIPS mode; Linux only",
        )
    return [
        os_check,
        _run(
            "openssl-fips-provider",
            p.openssl_fips_provider,
            "OpenSSL default properties are fips=yes and the fips provider is active",
            "OpenSSL is not using the FIPS provider by default",
        ),
        _run(
            "hashlib-openssl",
            p.hashlib_openssl,
            "hashlib.sha256 is served by OpenSSL",
            "hashlib.sha256 is not served by OpenSSL (built-in fallback)",
        ),
        _run(
            "kernel-fips",
            p.kernel_fips,
            f"{KERNEL_FIPS_FLAG} is 1",
            f"{KERNEL_FIPS_FLAG} is not 1",
        ),
    ]


def require_fips(probes: Probes | None = None) -> None:
    failed = [c for c in fips_status(probes) if not c.ok]
    if failed:
        raise FipsError("\n".join(f"{c.name}: {c.detail}" for c in failed))


def _read_ca_file(ca_file: str) -> str:
    """Read a trust store with one open, checking the opened file itself (no race).

    Symlinks are followed (RHEL bundle paths are symlinks): the target is checked.
    Refused: a relative path, anything but a regular file, a group- or world-writable
    file, or one owned by neither the current user nor root.
    """
    if not os.path.isabs(ca_file):
        raise PolicyError(f"ca_file {ca_file}: must be an absolute path")
    try:
        # O_NONBLOCK: opening a FIFO must not hang; regular-file reads are unaffected.
        fd = os.open(ca_file, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as e:
        raise PolicyError(f"ca_file {ca_file}: cannot read ({e.strerror})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PolicyError(f"ca_file {ca_file}: not a regular file")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PolicyError(f"ca_file {ca_file}: group- or world-writable")
        if st.st_uid not in (os.getuid(), 0):
            raise PolicyError(
                f"ca_file {ca_file}: owned by neither the current user nor root"
            )
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read()
    finally:
        os.close(fd)
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        raise PolicyError(f"ca_file {ca_file}: not a PEM bundle") from None


def _platform_store() -> dict[str, str]:
    """OpenSSL's compiled-in default store, ignoring SSL_CERT_FILE and SSL_CERT_DIR."""
    paths = ssl.get_default_verify_paths()
    store = {}
    if paths.openssl_cafile and os.path.isfile(paths.openssl_cafile):
        store["cafile"] = paths.openssl_cafile
    if paths.openssl_capath and os.path.isdir(paths.openssl_capath):
        store["capath"] = paths.openssl_capath
    if not store:
        raise PolicyError(
            f"no system trust store at {paths.openssl_cafile} or {paths.openssl_capath}; "
            "set ca_file for this endpoint"
        )
    return store


def upstream_ssl_context(ca_file: str | None, fips: bool) -> ssl.SSLContext:
    """TLS context for the upstream client: TLS 1.2 floor and verification, always.

    Trust store: `ca_file` when set, in either mode. Otherwise certifi's bundle, or in
    FIPS mode OpenSSL's compiled-in default store, which the platform manages and where
    RHEL and DoD roots are installed. Every store is passed explicitly, so SSL_CERT_FILE
    and SSL_CERT_DIR never change the trust roots. FIPS mode also limits TLS 1.2 to
    ECDHE with AES-GCM; TLS 1.3 suites are left to the FIPS provider.
    """
    if ca_file is not None:
        pem = _read_ca_file(ca_file)
        try:
            ctx = ssl.create_default_context(cadata=pem)
        except (ValueError, ssl.SSLError) as e:
            raise PolicyError(f"ca_file {ca_file}: cannot load ({e})") from None
    elif fips:
        ctx = ssl.create_default_context(**_platform_store())
    else:
        ctx = ssl.create_default_context(cafile=certifi.where())
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if fips:
        ctx.set_ciphers(FIPS_TLS12_CIPHERS)
    return ctx


def openssl_version() -> str:
    return ssl.OPENSSL_VERSION


def python_support(version_info, today: date) -> str:
    """Return "supported", "end-of-life" or "unknown" (a version not in PYTHON_EOL)."""
    eol = PYTHON_EOL.get(f"{version_info[0]}.{version_info[1]}")
    if eol is None:
        return "unknown"
    year, month = (int(x) for x in eol.split("-"))
    return "end-of-life" if (today.year, today.month) >= (year, month) else "supported"
