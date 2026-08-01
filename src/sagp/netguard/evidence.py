"""Evidence assembly, the invariant-13 verdict, signing, and the hash-chained ledger.

This module is the *judgment* half of the proof harness (``probes.py`` is the
*measurement* half). It never runs a probe; it takes structured results and:

* computes the verdict under CLAUDE.md **invariant 13** — a demonstration that
  cannot honestly say ``PASS`` says ``INVALID`` (could-not-conclude) or ``FAIL``
  (a control provably leaked) instead, and downgrades to
  ``PASS_WITH_OPEN_HIGH_SEVERITY_GAPS`` when a high-severity gap is OPEN;
* assembles the ``EVIDENCE-<gen>-<utc>`` report, signs its ``root_hash`` with the
  same self-signed Ed25519 key that signs the manifest (tamper-*evident*, not
  provenance — LIMITATIONS 5/6);
* appends one record to ``evidence/ledger.jsonl``, a plain SHA-256 hash chain
  (reusing ``audit.hashing``) whose head must be exported off-box to mean anything.

"The connection failed" proves nothing — it fails identically when the network is
merely absent. So a ``PASS`` is only ever reached when every invalidating
condition is false AND every assertion passed; the harness is built to withhold
it, not to grant it. Stdlib + ``cryptography`` (already a runtime dep) only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sagp.audit.hashing import GENESIS, canonical_json, chain_digest, sha256_hex

EVIDENCE_DIR_REL = Path("evidence")
LEDGER_REL = EVIDENCE_DIR_REL / "ledger.jsonl"
PRIVKEY_REL = Path(".airgap") / "keys" / "manifest_ed25519"

# --- the four verdicts (invariant 13) -----------------------------------------
PASS = "PASS"
PASS_WITH_OPEN_HIGH_SEVERITY_GAPS = "PASS_WITH_OPEN_HIGH_SEVERITY_GAPS"
INVALID = "INVALID"  # an invalidating condition fired — cannot conclude
FAIL = "FAIL"  # a control that should have held provably leaked


@dataclass(frozen=True)
class Assertion:
    """One numbered offline assertion: the egress probe + its paired control."""

    n: int
    name: str
    ok: bool
    detail: str = ""


@dataclass(frozen=True)
class Invalidator:
    """A condition from invariant 13 that, if triggered, forces ``INVALID``."""

    name: str
    triggered: bool
    detail: str = ""


@dataclass
class KnownGap:
    id: str
    severity: str  # low | medium | high
    status: str  # OPEN | CLOSED
    detail: str = ""


def compute_verdict(
    assertions: list[Assertion],
    invalidators: list[Invalidator],
    known_gaps: list[KnownGap],
) -> str:
    """The invariant-13 decision. Order matters: invalidation dominates a leak,
    a leak dominates a gap, a high-severity OPEN gap dominates a clean PASS.

    * any invalidator triggered            -> INVALID   (could not conclude)
    * else any assertion failed            -> FAIL      (a control leaked)
    * else a high-severity OPEN gap exists -> PASS_WITH_OPEN_HIGH_SEVERITY_GAPS
    * else                                 -> PASS
    """
    if any(inv.triggered for inv in invalidators):
        return INVALID
    if any(not a.ok for a in assertions):
        return FAIL
    if any(g.severity == "high" and g.status == "OPEN" for g in known_gaps):
        return PASS_WITH_OPEN_HIGH_SEVERITY_GAPS
    return PASS


def is_pass(verdict: str) -> bool:
    """A green verdict for gating. ``PASS_WITH_OPEN_HIGH_SEVERITY_GAPS`` counts as
    non-blocking-green; ``INVALID`` and ``FAIL`` never do."""
    return verdict in (PASS, PASS_WITH_OPEN_HIGH_SEVERITY_GAPS)


def now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sign(root_hash: str, root: Path) -> dict[str, str] | None:
    """Sign ``root_hash`` with the host Ed25519 key, or None if it is absent."""
    priv = root / PRIVKEY_REL
    if not priv.exists():
        return None
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = serialization.load_pem_private_key(priv.read_bytes(), password=None)
    if not isinstance(sk, Ed25519PrivateKey):
        raise TypeError(f"manifest signing key is not Ed25519 ({type(sk).__name__})")
    sig = sk.sign(root_hash.encode())
    pub_raw = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {"alg": "ed25519", "key_id": sha256_hex(pub_raw)[:16], "sig": sig.hex()}


def build_report(
    *,
    seal_generation: int,
    phase: str,
    guard_mode: str,
    verdict: str,
    assertions: list[Assertion],
    invalidators: list[Invalidator],
    known_gaps: list[KnownGap],
    manifest: dict[str, Any],
    online_negative_control: dict[str, Any],
    host: dict[str, Any],
    root: Path | None = None,
) -> dict[str, Any]:
    """Assemble the evidence report and bind it with a signed ``root_hash``.

    ``root_hash`` is SHA-256 over the canonical JSON of every field except the
    signature itself, so the signature covers the whole verdict, not just a
    digest handed to it.
    """
    root = root or Path.cwd()
    body: dict[str, Any] = {
        "evidence_version": 1,
        "seal_generation": seal_generation,
        "generated_ts": now_utc(),
        "verdict": verdict,
        "phase": phase,
        "guard_mode": guard_mode,
        "assertions": [
            {"n": a.n, "name": a.name, "ok": a.ok, "detail": a.detail} for a in assertions
        ],
        "invalidating_conditions": [
            {"name": i.name, "triggered": i.triggered, "detail": i.detail} for i in invalidators
        ],
        "known_gaps": [
            {"id": g.id, "severity": g.severity, "status": g.status, "detail": g.detail}
            for g in known_gaps
        ],
        "manifest": manifest,
        "online_negative_control": online_negative_control,
        "host": host,
    }
    root_hash = sha256_hex(canonical_json(body))
    body["root_hash"] = root_hash
    sig = _sign(root_hash, root)
    if sig is not None:
        body["signature"] = sig
    return body


# --- the hash-chained ledger --------------------------------------------------


def ledger_head(root: Path | None = None) -> str:
    """The last record's ``chain_digest``, or GENESIS if the ledger is empty."""
    path = (root or Path.cwd()) / LEDGER_REL
    if not path.exists():
        return GENESIS
    last = GENESIS
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        import json

        last = str(json.loads(line).get("chain_digest", last))
    return last


def append_ledger(
    *,
    seal_generation: int,
    evidence_root_hash: str,
    verdict: str,
    root: Path | None = None,
) -> dict[str, Any]:
    """Append one link binding this evidence to the previous head. Returns the record."""
    root = root or Path.cwd()
    prev = ledger_head(root)
    record: dict[str, Any] = {
        "ts": now_utc(),
        "seal_generation": seal_generation,
        "evidence_root_hash": evidence_root_hash,
        "verdict": verdict,
        "prev_hash": prev,
    }
    record["chain_digest"] = chain_digest(record)
    path = root / LEDGER_REL
    path.parent.mkdir(parents=True, exist_ok=True)
    import json

    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
    return record


@dataclass
class LedgerCheck:
    ok: bool
    length: int = 0
    head: str = GENESIS
    break_index: int | None = None
    problem: str = ""


def verify_ledger(root: Path | None = None) -> LedgerCheck:
    """Walk the chain: each record's recomputed digest must match, and its
    ``prev_hash`` must equal the prior record's ``chain_digest``. A break is
    reported at the exact index (invariant 13: a broken chain is invalidating)."""
    path = (root or Path.cwd()) / LEDGER_REL
    if not path.exists():
        return LedgerCheck(ok=True, length=0, head=GENESIS)  # empty chain is intact
    import json

    prev = GENESIS
    count = 0
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        stored = rec.get("chain_digest")
        recomputed = chain_digest({k: v for k, v in rec.items() if k != "chain_digest"})
        if rec.get("prev_hash") != prev:
            return LedgerCheck(False, count, prev, idx, "prev_hash does not match prior digest")
        if stored != recomputed:
            return LedgerCheck(False, count, prev, idx, "chain_digest mismatch (record altered)")
        prev = str(stored)
        count += 1
    return LedgerCheck(ok=True, length=count, head=prev)


def known_gaps_from_metrics(root: Path | None = None) -> list[KnownGap]:
    """Read the OPEN gaps recorded by ``make eval`` in docs/metrics/latest.json."""
    path = (root or Path.cwd()) / "docs" / "metrics" / "latest.json"
    if not path.exists():
        return []
    import json

    data = json.loads(path.read_text(encoding="utf-8"))
    out: list[KnownGap] = []
    for g in data.get("known_gaps", []):
        out.append(
            KnownGap(
                id=str(g.get("metric", g.get("id", "?"))),
                severity=str(g.get("severity", "medium")),
                status=str(g.get("status", "OPEN")),
                detail=str(g.get("cause", "")),
            )
        )
    return out
