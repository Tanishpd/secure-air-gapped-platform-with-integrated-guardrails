#!/usr/bin/env python
"""make ingest FILE=<path.pdf> COLLECTION=<name> — ingest a local PDF through the
SAME guarded pipeline the app uses (every chunk document-surface scanned;
quarantined chunks diverted to the never-retrieved sibling). Idempotent."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sagp.app.bootstrap import build_engines  # noqa: E402
from sagp.config import load_settings  # noqa: E402
from sagp.rag.ingest import ingest_pdf  # noqa: E402


def main() -> int:
    file = (sys.argv[1] if len(sys.argv) > 1 else "") or os.environ.get("FILE", "")
    collection = (sys.argv[2] if len(sys.argv) > 2 else "") or os.environ.get("COLLECTION", "")
    if not file or not collection:
        sys.stderr.write("usage: make ingest FILE=<path.pdf> COLLECTION=<name>\n")
        return 2

    engines = build_engines(load_settings(), root=ROOT)
    assert engines.chunk_tokenizer is not None
    r = ingest_pdf(
        Path(file),
        collection=collection,
        store=engines.store,
        embedder=engines.embedder,
        chunk_tokenizer=engines.chunk_tokenizer,
        scanner=engines.injection_scanner,
        policy=engines.policy,
    )
    print(
        f"ingested {r.source} -> {collection}: indexed={r.chunks_indexed} "
        f"(suspect={r.chunks_suspect}) quarantined={r.chunks_quarantined} "
        f"pages_quarantined={len(r.pages_quarantined)}  doc={r.doc_sha256[:12]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
