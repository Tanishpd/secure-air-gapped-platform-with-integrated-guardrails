"""The invariant-13 verdict logic, the signed evidence report, and the
hash-chained ledger — the judgment half of the M13 proof harness.

All pure/tmp: no probes, no real key. The signature test mints an ephemeral
Ed25519 key in the temp root so it is self-contained.
"""

from __future__ import annotations

import json
from pathlib import Path

from sagp.audit.hashing import canonical_json, sha256_hex
from sagp.netguard import evidence as ev
from sagp.netguard.evidence import Assertion, Invalidator, KnownGap


def _ok_assertions(n: int = 3) -> list[Assertion]:
    return [Assertion(i, f"a{i}", True) for i in range(1, n + 1)]


def _no_invalidators() -> list[Invalidator]:
    return [Invalidator("x", False), Invalidator("y", False)]


# --- compute_verdict: the invariant-13 truth table ---------------------------


def test_all_green_is_pass() -> None:
    assert ev.compute_verdict(_ok_assertions(), _no_invalidators(), []) == ev.PASS


def test_any_invalidator_forces_invalid() -> None:
    invs = [Invalidator("phase_not_operate", True, "phase=PROVISION")]
    assert ev.compute_verdict(_ok_assertions(), invs, []) == ev.INVALID


def test_failed_assertion_is_fail_when_not_invalidated() -> None:
    assertions = [Assertion(1, "a1", True), Assertion(2, "a2", False)]
    assert ev.compute_verdict(assertions, _no_invalidators(), []) == ev.FAIL


def test_invalidator_dominates_a_failed_assertion() -> None:
    # Cannot conclude wins over a leak: INVALID, not FAIL.
    assertions = [Assertion(1, "a1", False)]
    invs = [Invalidator("guard_not_installed", True)]
    assert ev.compute_verdict(assertions, invs, []) == ev.INVALID


def test_high_open_gap_downgrades_pass() -> None:
    gaps = [KnownGap("jailbreak", "high", "OPEN")]
    assert (
        ev.compute_verdict(_ok_assertions(), _no_invalidators(), gaps)
        == ev.PASS_WITH_OPEN_HIGH_SEVERITY_GAPS
    )


def test_medium_open_gap_does_not_downgrade() -> None:
    gaps = [KnownGap("benign_fpr", "medium", "OPEN")]
    assert ev.compute_verdict(_ok_assertions(), _no_invalidators(), gaps) == ev.PASS


def test_closed_high_gap_does_not_downgrade() -> None:
    gaps = [KnownGap("old", "high", "CLOSED")]
    assert ev.compute_verdict(_ok_assertions(), _no_invalidators(), gaps) == ev.PASS


def test_is_pass_semantics() -> None:
    assert ev.is_pass(ev.PASS)
    assert ev.is_pass(ev.PASS_WITH_OPEN_HIGH_SEVERITY_GAPS)
    assert not ev.is_pass(ev.INVALID)
    assert not ev.is_pass(ev.FAIL)


# --- the hash-chained ledger --------------------------------------------------


def _append(tmp_path: Path, h: str) -> dict[str, object]:
    return ev.append_ledger(
        seal_generation=0, evidence_root_hash=h * 64, verdict="PASS", root=tmp_path
    )


def test_ledger_appends_and_chains(tmp_path: Path) -> None:
    r1 = _append(tmp_path, "a")
    r2 = _append(tmp_path, "b")
    assert r1["prev_hash"] == ev.GENESIS
    assert r2["prev_hash"] == r1["chain_digest"]
    check = ev.verify_ledger(tmp_path)
    assert check.ok and check.length == 2 and check.head == r2["chain_digest"]


def test_empty_ledger_is_intact(tmp_path: Path) -> None:
    check = ev.verify_ledger(tmp_path)
    assert check.ok and check.length == 0 and check.head == ev.GENESIS


def test_ledger_detects_altered_record(tmp_path: Path) -> None:
    _append(tmp_path, "a")
    _append(tmp_path, "b")
    path = tmp_path / ev.LEDGER_REL
    lines = path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["verdict"] = "INVALID"  # tamper: flip the verdict, leave chain_digest stale
    lines[1] = json.dumps(rec, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    check = ev.verify_ledger(tmp_path)
    assert not check.ok and check.break_index == 1


def test_ledger_detects_broken_prev_link(tmp_path: Path) -> None:
    _append(tmp_path, "a")
    _append(tmp_path, "b")
    path = tmp_path / ev.LEDGER_REL
    lines = path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["prev_hash"] = "0" * 64  # break the link (recompute so digest matches its own body)
    from sagp.audit.hashing import chain_digest

    rec["chain_digest"] = chain_digest({k: v for k, v in rec.items() if k != "chain_digest"})
    lines[1] = json.dumps(rec, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    check = ev.verify_ledger(tmp_path)
    assert not check.ok and check.break_index == 1


# --- build_report: root_hash binds the body, signature round-trips ------------


def test_report_root_hash_binds_body_and_signature_verifies(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    keydir = tmp_path / ".airgap" / "keys"
    keydir.mkdir(parents=True)
    sk = Ed25519PrivateKey.generate()
    (keydir / "manifest_ed25519").write_bytes(
        sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    report = ev.build_report(
        seal_generation=2,
        phase="OPERATE",
        guard_mode="enforce",
        verdict=ev.PASS,
        assertions=_ok_assertions(),
        invalidators=_no_invalidators(),
        known_gaps=[],
        manifest={"root_hash": "deadbeef", "signature_valid": True},
        online_negative_control={"present": True, "all_probes_blocked": True},
        host={"platform": "darwin"},
        root=tmp_path,
    )
    body = {k: v for k, v in report.items() if k not in ("root_hash", "signature")}
    assert sha256_hex(canonical_json(body)) == report["root_hash"]
    sk.public_key().verify(bytes.fromhex(report["signature"]["sig"]), report["root_hash"].encode())


def test_report_without_key_has_no_signature(tmp_path: Path) -> None:
    report = ev.build_report(
        seal_generation=0,
        phase="PROVISION",
        guard_mode="enforce",
        verdict=ev.INVALID,
        assertions=_ok_assertions(),
        invalidators=[Invalidator("phase_not_operate", True)],
        known_gaps=[],
        manifest={"root_hash": None, "signature_valid": None},
        online_negative_control={"present": False, "all_probes_blocked": False},
        host={},
        root=tmp_path,
    )
    assert "signature" not in report
    assert report["verdict"] == ev.INVALID and report["root_hash"]
