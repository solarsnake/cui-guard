# FIPS mode deployment guide

FIPS 140-3 validates cryptographic modules, not applications. cui-guard is not a cryptographic module and is not validated. In FIPS mode it uses the platform's FIPS 140-3 validated module, and it refuses to start unless that module is the one in use.

## What FIPS mode is

Set `fips = "require"` in the user config or the organization policy. The built-in default is `off`. Layers merge strictest: if any layer says `require`, the result is `require`. An organization can impose it and a user cannot undo it. A user setting `require` is a tightening, so it needs no OS authentication.

With `require`, the launcher and the gateway both run four checks before anything listens. If any check fails they exit non-zero and name each failed check:

| Check | Passes when | How it is detected |
|---|---|---|
| `os` | The OS is Linux. | `platform.system()`. macOS is always refused: python.org and Homebrew Python link their own OpenSSL, not Apple's validated corecrypto. |
| `openssl-fips-provider` | The OpenSSL FIPS provider serves this process's TLS and hashing. | `_hashlib.get_fips_mode()` must return 1. Then, for the libcrypto that `_hashlib` loaded and the one `_ssl` loaded, `EVP_default_properties_is_fips_enabled(NULL)` must return 1 and `OSSL_PROVIDER_available(NULL, "fips")` must return 1. The libraries are reached through the loaded extension modules' own shared objects, so the check reads the OpenSSL the interpreter really uses, with no path guessed. A `fips=yes` default property without an active FIPS provider fails. |
| `hashlib-openssl` | `hashlib.sha256` is OpenSSL's, not CPython's built-in HACL* fallback, which is not validated. | `hashlib.sha256` must be `_hashlib.openssl_sha256`, the object it returns must be an OpenSSL `_hashlib.HASH`, and a known-answer test (SHA-256 of `abc`) must match. |
| `kernel-fips` | The kernel is in FIPS mode, so the CSPRNG behind `secrets` is too. | `/proc/sys/crypto/fips_enabled` is `1`. |

A probe that raises an error counts as a failed check.

## What FIPS mode covers

- **TLS to the model endpoint.** Every upstream connection uses TLS 1.2 or later with certificate verification, in all modes. In FIPS mode TLS 1.2 is further limited to ECDHE key exchange with AES-GCM (`ECDHE+AESGCM`). TLS 1.3 suites are left to the FIPS provider.
- **Hashing.** SHA-256 for audit, cache and request digests.
- **Randomness.** `secrets` for the session token and IDs, drawn from the kernel CSPRNG.

It does not cover:

- the rest of the Python interpreter and the libraries cui-guard runs on, which are not cryptographic modules;
- whatever is behind the model endpoint. FIPS mode protects the connection to the endpoint, not what the endpoint does with the data.

## Supported platforms

- **RHEL 9** (or a rebuild that ships Red Hat's FIPS provider) with the system switched to FIPS mode (`fips-mode-setup --enable`, then reboot). Use the distribution's Python (`python3.12` from the RHEL repositories), which links the system OpenSSL and its FIPS provider.
- **Ubuntu Pro with the FIPS packages** enabled (`pro enable fips-updates` or `fips`), with the distribution's Python.

Python from python.org, Homebrew, pyenv or uv's standalone builds carries its own OpenSSL, which has no FIPS provider. Those interpreters fail `openssl-fips-provider`.

## Install

Install from the hash lock with the distribution's Python, so no unpinned package is fetched:

```
python3.12 -m venv /opt/cui-guard
/opt/cui-guard/bin/pip install --require-hashes -r runtime.lock.txt
/opt/cui-guard/bin/pip install --no-deps cui_guard-<version>-py3-none-any.whl
```

Verify the wheel first, as described in [SECURITY-ASSURANCE.md](SECURITY-ASSURANCE.md).

Then set `fips = "require"` in the organization policy (`/etc/cui-guard/policy.toml`).

## Check the result with `doctor`

```
cui-guard doctor --require-fips
```

`doctor` prints the Python version and whether it is still under upstream security support, the OpenSSL version, each FIPS check with `ok` or `FAIL`, the TLS minimum version and the effective `fips` setting. It never prints credentials, tokens or identifiers. With `--require-fips` it exits 1 if any check fails, so it can gate a deployment script.

## Trust store for internal endpoints

An endpoint can set `ca_file`, an absolute path to a PEM bundle that replaces the default trust store for that endpoint. This is how an internal model server with a DoD PKI or other internal certificate is trusted. `ca_file` replaces the store in FIPS mode and outside it. Without `ca_file`, FIPS mode uses the compiled-in default store of the interpreter's OpenSSL, which the platform manages (on RHEL, the system trust store, where DoD roots added with `update-ca-trust` also land). Outside FIPS mode the default is certifi's public bundle. Both modes ignore `SSL_CERT_FILE` and `SSL_CERT_DIR`; put a corporate or TLS-inspection CA in `ca_file`.

```
[endpoints.internal]
url = "https://llm.internal.example.mil"
formats = ["openai-chat"]
trust = "approved"
ca_file = "/etc/pki/cui-guard/dod-roots.crt"
```

The gateway refuses a `ca_file` that is a relative path, group- or world-writable, or owned by neither the current user nor root. It opens the file once and checks that opened file, following symlinks to the target. Adding or changing `ca_file` in the user layer is a loosening and needs OS authentication. Approval covers the path, not the file's contents, so keep organization bundles root-owned.

## Certificates belong to the platform vendor

The CMVP certificate belongs to the platform vendor's module, for example the Red Hat Enterprise Linux OpenSSL FIPS provider or Canonical's FIPS OpenSSL. Cite the vendor's certificate number for the exact OS release you deploy, from the vendor's compliance pages or the CMVP validated-modules list. cui-guard has no certificate of its own.

## How this is tested

- Unit tests (`tests/test_fips.py`) inject every probe, so each pass and fail path runs on any host.
- `scripts/check fips` runs `tests/fips` inside a Red Hat UBI 9 container (`registry.access.redhat.com/ubi9/python-312`, pinned by digest) with the FIPS provider forced on through `OPENSSL_CONF` (`tests/fips/openssl-fips.cnf`). It checks the provider and hashlib checks pass, that MD5 is refused, and that a real TLS handshake succeeds with the FIPS context, using GCM suites. The kernel check cannot pass in a container, so it is covered only by the unit tests. Without Docker the gate prints `SKIPPED (docker not available)`. CI runs it in its own `fips` job.
