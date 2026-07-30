"""Audit hash-chain verification.

Walks the JSONL, recomputing each record's ``chain_digest`` and checking that its
``prev_hash`` equals the previous record's digest. Returns the index of the first
break, so ``make audit-verify`` can point at exactly where the chain was cut,
reordered, or mutated. Reads the file bytes — never trusts an in-memory model.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

from sagp.audit.hashing import GENESIS, chain_digest


@dataclass
class ChainResult:
    ok: bool
    records: int
    head: str
    break_index: int | None = None  # 0-based line index of the first broken record
    problem: str | None = None


def verify_chain(path: Path) -> ChainResult:
    if not path.exists():
        return ChainResult(ok=True, records=0, head=GENESIS)

    prev = GENESIS
    count = 0
    with path.open("r", encoding="utf-8") as fh:
        for idx, line in enumerate(fh):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                rec = json.loads(stripped)
            except json.JSONDecodeError:
                return ChainResult(False, count, prev, idx, "unparseable line")

            stored = rec.get("chain_digest")
            if rec.get("prev_hash") != prev:
                return ChainResult(False, count, prev, idx, "prev_hash does not match previous digest")

            payload = {k: v for k, v in rec.items() if k != "chain_digest"}
            recomputed = chain_digest(payload)
            if recomputed != stored:
                return ChainResult(False, count, prev, idx, "chain_digest mismatch (record mutated)")

            prev = str(stored)
            count += 1

    return ChainResult(ok=True, records=count, head=prev)


def _main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd() / "audit" / "audit.jsonl"
    res = verify_chain(path)
    if res.ok:
        print(f"AUDIT CHAIN OK — {res.records} records, head={res.head[:16]}…")
        return 0
    print(
        f"AUDIT CHAIN BROKEN at record {res.break_index}: {res.problem} "
        f"({res.records} valid records before the break)",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(_main())
