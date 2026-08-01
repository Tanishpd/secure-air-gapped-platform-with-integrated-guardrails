# syntax=docker/dockerfile:1
#
# App image for a LINUX deployment shape. Read these caveats before relying on it:
#
#  - The primary, thesis-aligned deployment is the sealed macOS/M2 host via
#    `bin/sagp-serve` (Apple unified-memory budgets, launchd, pf, FileVault). This
#    image is a DIFFERENT shape (a Linux host/enclave). The RAM budgets in
#    `netguard/budget.py` are macOS projections and do NOT transfer unchanged —
#    re-measure on the target.
#  - Model weights are NOT baked in (invariant 4: not redistributable; audit/PII
#    must never live in an image). Mount a provisioned `models/` (incl.
#    `MANIFEST.json`) read-only at runtime — the app full-verifies it against the
#    manifest at boot and refuses to start on a mismatch.
#  - No hash-pinned lock is used here: the repo pins runtime deps in
#    `pyproject.toml` (`[project].dependencies`, all `==`). A production build
#    should generate a platform-matched hash-pinned lock on THIS base image and
#    install with `--require-hashes`. `setuptools>=83.0.0` closes PYSEC-2026-3447
#    (`make audit-deps`).
#  - The app binds loopback by design (invariant 11). Run with `--network host`
#    so the container's 127.0.0.1 is the host's — reaching the sibling Ollama at
#    127.0.0.1:11434 and exposing the API only on host loopback. Egress control is
#    host `pf` (ADR-0002), NOT this container; compose options do not isolate it.
#
FROM python:3.11-slim AS runtime

# Never phone home (invariant 10): the egress guard would raise EgressViolation,
# but set these before any import as belt-and-suspenders.
ENV HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SAGP_BIND_HOST=127.0.0.1 \
    SAGP_BIND_PORT=8000

RUN useradd --create-home --uid 10001 sagp
WORKDIR /app

# Deps first for layer caching; the package installs from pinned pyproject deps.
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --upgrade pip "setuptools>=83.0.0" \
 && python -m pip install -e .

# Config, launcher, and the .pth-style guard bootstrap travel with the code.
COPY config ./config
COPY bin ./bin
COPY airgap_guard_boot.py ./

# models/ (weights + MANIFEST.json) and .airgap/state.json are supplied at RUNTIME
# via read-only mounts — never baked. Pre-create the mount points, app-owned.
RUN mkdir -p models data/qdrant audit evidence .airgap \
 && chown -R sagp:sagp /app
USER sagp

EXPOSE 8000

# Buffered, single worker, loopback (invariant 11). Boot runs the four fail-closed
# gates: manifest full-verify -> RSS budget -> engine build -> injection self-test.
# Requires models/ mounted read-only, or it refuses to start (by design).
CMD ["python", "-m", "sagp"]
