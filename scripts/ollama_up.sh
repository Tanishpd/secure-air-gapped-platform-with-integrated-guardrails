#!/usr/bin/env bash
# make ollama-up — install + load the ai.sagp.ollama launchd agent (loopback-bound
# `ollama serve` with sagp's pinned env). ONE supported way to run Ollama for the
# sealed box; skip it if you already run Ollama some other way. `make ollama-down`
# unloads it. No sudo (a per-user LaunchAgent).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$ROOT/deploy/launchd/ai.sagp.ollama.plist"
AGENTS="$HOME/Library/LaunchAgents"
DEST="$AGENTS/ai.sagp.ollama.plist"
OLLAMA_BIN="$(command -v ollama || true)"

[ -n "$OLLAMA_BIN" ] || { echo "ollama-up: ollama not on PATH" >&2; exit 1; }
mkdir -p "$AGENTS" "$ROOT/models/ollama"

# Substitute the live paths into the template (never commit an absolute-path copy).
sed -e "s#__OLLAMA_BIN__#$OLLAMA_BIN#g" -e "s#__REPO_ROOT__#$ROOT#g" "$TEMPLATE" > "$DEST"
echo "ollama-up: wrote $DEST"

launchctl unload "$DEST" 2>/dev/null || true
launchctl load "$DEST"
echo "ollama-up: loaded ai.sagp.ollama (ollama serve on 127.0.0.1:11434)"
echo "  verify:  curl -sS http://127.0.0.1:11434/api/tags"
echo "  stop:    make ollama-down"
