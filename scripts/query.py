"""make query Q="<question>" [COLLECTION=<name>] — one guarded chat request from
the CLI, through the full C0–C26 path against the real Ollama.

The CLI principal holds chat/ingest/pii:reveal (a local operator on the box);
rehydration to real values still requires SAGP_REHYDRATE_OUTPUT=1, so by default
the answer carries `<PERSON_1>`-style placeholders, not raw PII."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sagp.app.bootstrap import build_engines  # noqa: E402
from sagp.config import load_settings  # noqa: E402
from sagp.app.routes.chat import run_chat  # noqa: E402
from sagp.errors import SagpError  # noqa: E402
from sagp.types import Principal  # noqa: E402


def main() -> int:
    question = (sys.argv[1] if len(sys.argv) > 1 else "") or os.environ.get("Q", "")
    collection = (sys.argv[2] if len(sys.argv) > 2 else "") or os.environ.get("COLLECTION", "handbook")
    if not question:
        sys.stderr.write('usage: make query Q="<question>" [COLLECTION=<name>]\n')
        return 2

    engines = build_engines(load_settings(), root=ROOT)
    principal = Principal(id="cli", scopes=frozenset({"chat", "ingest", "pii:reveal"}))
    scanned: list[str] = []
    try:
        resp = run_chat(question, collection, principal, engines, scanned=scanned)
    except SagpError as exc:
        sys.stderr.write(f"[{exc.code}] {exc}\n")
        return 1
    print(resp.answer)
    print(f"\n— decision: {resp.decision}   citations: {resp.citations}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
