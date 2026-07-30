#!/usr/bin/env bash
# 05 — pull + save the Docker images for PROFILE=demo/proof.
# OPTIONAL: the default runtime backend is embedded Qdrant, which needs no Docker.
# Skips cleanly (exit 0) if the daemon is not running, so `make provision` on the
# default embedded path does not require Docker Desktop to be up.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEST="$ROOT/models/docker"
mkdir -p "$DEST"

log() { echo "[05_docker] $*"; }

if ! docker info >/dev/null 2>&1; then
  log "Docker daemon not running — SKIPPING (embedded Qdrant is the default backend)."
  log "Run 'open -a Docker' and re-run only if you want PROFILE=demo/proof."
  exit 0
fi

IMAGES=("qdrant/qdrant:v1.18.3-unprivileged" "alpine:3")
for img in "${IMAGES[@]}"; do
  log "pull $img"
  docker pull "$img"
  digest="$(docker inspect --format '{{index .RepoDigests 0}}' "$img" 2>/dev/null || echo "unknown")"
  log "  digest: $digest"
  tar="$DEST/$(echo "$img" | tr '/:' '--').tar"
  log "  docker save -> $(basename "$tar")"
  docker save -o "$tar" "$img"
done
log "done"
