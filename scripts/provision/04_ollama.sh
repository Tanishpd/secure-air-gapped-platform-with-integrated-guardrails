#!/usr/bin/env bash
# 04 — pull the Ollama models into the repo (OLLAMA_MODELS points inside models/).
# Skips llama3:8b by design (does not fit in 8 GB RAM; disk-constrained host —
# AIRGAP_RUNBOOK pre-provision checklist). Starts a loopback-bound ollama serve
# if one is not already running.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export OLLAMA_MODELS="$ROOT/models/ollama"
export OLLAMA_HOST="127.0.0.1:11434"
mkdir -p "$OLLAMA_MODELS"

log() { echo "[04_ollama] $*"; }

# Models to pull (llama3:8b intentionally omitted).
TAGS=("llama3.2:3b-instruct-q4_K_M" "llama3.2:1b")

started_server=0
if ! curl -sf -o /dev/null "http://${OLLAMA_HOST}/api/version" 2>/dev/null; then
  log "starting ollama serve (loopback), OLLAMA_MODELS=$OLLAMA_MODELS"
  ollama serve > "$ROOT/models/ollama/serve.log" 2>&1 &
  started_server=1
  for _ in $(seq 1 30); do
    curl -sf -o /dev/null "http://${OLLAMA_HOST}/api/version" 2>/dev/null && break
    sleep 1
  done
fi

curl -sf -o /dev/null "http://${OLLAMA_HOST}/api/version" || { echo "[04_ollama] FAIL: ollama server not reachable"; exit 1; }

for tag in "${TAGS[@]}"; do
  log "pulling $tag"
  ollama pull "$tag"
done

log "installed tags:"
ollama list

if [ "$started_server" = "1" ]; then
  log "stopping the ollama serve we started"
  pkill -f "ollama serve" 2>/dev/null || true
fi
log "done"
