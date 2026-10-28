#!/usr/bin/env bash
# Run tests/fips in Red Hat UBI 9 with the OpenSSL FIPS provider forced on (design 8.3).
# Called by `scripts/check fips`. The repository is mounted read-only; dependencies are
# installed inside the throwaway container from the hash-pinned lock files.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# registry.access.redhat.com/ubi9/python-312:latest, resolved 2026-10-27 with
# `docker buildx imagetools inspect` (multi-arch index digest: amd64, arm64, s390x, ppc64le).
IMAGE="registry.access.redhat.com/ubi9/python-312@sha256:105e70cb265e82beef1687b87b77444a05b410c55d8631e9aa9aa6804fcca45d"

docker run --rm \
  --volume "$ROOT:/src:ro" \
  --workdir /src \
  --env PYTHONDONTWRITEBYTECODE=1 \
  --env PIP_DISABLE_PIP_VERSION_CHECK=1 \
  --entrypoint /bin/bash \
  "$IMAGE" -c '
set -euo pipefail
# Installs run without the FIPS configuration; only the tests run under it.
python3 -m pip install --quiet --no-deps --require-hashes -r requirements/runtime.lock.txt
# pytest is not a runtime dependency: take it and its dependencies, hashes included,
# from the dev lock rather than resolving anything new.
python3 - requirements/dev.lock.txt >/tmp/pytest.lock.txt <<"PY"
import re
import sys

want = {"pytest", "pytest-asyncio", "iniconfig", "packaging", "pluggy", "pygments", "typing-extensions"}
seen, keep, out = set(), False, []
for line in open(sys.argv[1], encoding="utf-8"):
    m = re.match(r"([A-Za-z0-9_.-]+)==", line)
    if m:
        keep = m.group(1).lower() in want
        if keep:
            seen.add(m.group(1).lower())
    elif not line.startswith(" "):
        keep = False
    if keep and not line.lstrip().startswith("#"):
        out.append(line)
missing = want - seen
if missing:
    sys.exit(f"not in requirements/dev.lock.txt: {sorted(missing)}")
sys.stdout.write("".join(out))
PY
python3 -m pip install --quiet --no-deps --require-hashes -r /tmp/pytest.lock.txt
export OPENSSL_CONF=/src/tests/fips/openssl-fips.cnf CUI_GUARD_FIPS_CONTAINER=1 PYTHONPATH=/src/src
openssl list -providers
python3 -m pytest -q -p no:cacheprovider -rs tests/fips
'
