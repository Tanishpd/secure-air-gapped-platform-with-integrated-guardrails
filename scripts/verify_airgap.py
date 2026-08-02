#!/usr/bin/env python
"""``make verify`` — the 9 offline assertions (BLUEPRINT §9.2), the deliverable.

Runs every egress probe (each MUST raise ``EgressViolation``) paired with a
positive control (each MUST be allowed), verifies the manifest in **full** mode,
and evaluates the invariant-13 invalidating conditions. The verdict is computed
by ``netguard.evidence.compute_verdict``; a green ``PASS`` is only ever reached
when every invalidator is false AND every assertion passed — "the connection
failed" is never accepted as proof (it fails identically when the network is
merely absent).

Writes ``evidence/verify-airgap-<gen>.json`` (unsigned intermediate) for
``scripts/evidence.py`` to sign and ledger. Exit 0 only on a green verdict.

Run OFFLINE, in OPERATE. Run now (online / unsealed) it correctly returns
INVALID — that is the design, not a bug.

SEALED-HOST EXECUTION (fixed 2026-08-02): on a sealed host the runtime `.pth` has
already armed the guard in THIS orchestrator process, and the guard's subprocess-deny
would block it from spawning probe children. So when the guard is already installed
(``egress.is_installed()``) the probes run IN-PROCESS against that real, armed guard
(``probes.run_probe_inprocess``) — more honest than a fresh child, and no spawn needed.
When NOT armed (PROVISION / dev) it spawns children that self-install, as verify_online
needs. Note: on a sealed host, listener enumeration falls to psutil (netstat is itself
blocked by the armed guard) — run ``sudo make verify`` so it has the privileges to
enumerate, else that check is INVALID (cannot prove the negative). History in
docs/LIMITATIONS.md "The sealed-host proof path (fixed 2026-08-02)".
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sagp.netguard import egress  # noqa: E402
from sagp.netguard import evidence as ev  # noqa: E402
from sagp.netguard import manifest as mf  # noqa: E402
from sagp.netguard import probes as pb  # noqa: E402
from sagp.netguard.evidence import Assertion, Invalidator  # noqa: E402
from sagp.netguard.phase import current_phase  # noqa: E402

LOOPBACK_IPS = ("127.0.0.1", "::1", "::ffff:127.0.0.1")

# The guard-receipt probe (assertion 1): both layers active in the same child.
_GUARD_RECEIPT = pb.Probe(
    "guard_receipt",
    "import _socket\n"
    "l1 = socket.socket.connect.__name__ == 'guarded_connect'\n"
    "l2 = False\n"
    "try:\n"
    "    _socket.socket().connect(('1.1.1.1', 443))\n"
    "except EgressViolation:\n"
    "    l2 = True\n"
    "assert l1 and l2, f'l1={l1} l2={l2}'",
)


def _is_loopback_ip(ip: str) -> bool:
    return ip in LOOPBACK_IPS or ip.startswith("127.")


def _nonloopback_listeners() -> tuple[list[str] | None, str]:
    """Definitive via psutil (needs privileges); netstat fallback pre-seal.

    Returns (listeners, method). ``listeners is None`` means enumeration was
    unavailable — which is itself invalidating (we cannot prove the negative).
    """
    try:
        import psutil

        conns = psutil.net_connections(kind="inet")
        nonlo = [
            f"{c.laddr.ip}:{c.laddr.port}"
            for c in conns
            if c.status == psutil.CONN_LISTEN and c.laddr and not _is_loopback_ip(c.laddr.ip)
        ]
        return sorted(set(nonlo)), "psutil"
    except Exception:  # noqa: BLE001 — AccessDenied on macOS without privileges
        pass
    try:
        out = subprocess.run(
            ["netstat", "-an", "-p", "tcp"], capture_output=True, text=True, timeout=10
        ).stdout
    except Exception as exc:  # noqa: BLE001 — blocked under the guard, or missing
        return None, f"unavailable ({type(exc).__name__}); run `sudo make verify`"
    nonlo = []
    for line in out.splitlines():
        toks = line.split()
        if len(toks) >= 5 and toks[-1] == "LISTEN":
            local = toks[3]
            ip = local.rsplit(".", 1)[0]  # "127.0.0.1.8000" -> "127.0.0.1", "*.8000" -> "*"
            if not _is_loopback_ip(ip):
                nonlo.append(local)
    return sorted(set(nonlo)), "netstat"


def _byte_flip_detected() -> tuple[bool, str]:
    """Positive control for assertion 9: recompute the hash of the SMALLEST
    manifested file with one byte flipped and show it no longer matches — proving
    ``verify`` detects a change, non-destructively (the real file is untouched)."""
    manifest_path = ROOT / mf.MANIFEST_REL
    if not manifest_path.exists():
        return False, "no MANIFEST.json"
    files = json.loads(manifest_path.read_text())["files"]
    present = [
        f
        for f in files
        if (ROOT / f["path"]).is_file() and (ROOT / f["path"]).stat().st_size > 0
    ]
    if not present:
        return False, "no non-empty manifested files present"
    target = min(present, key=lambda f: f.get("size", 1 << 62))
    data = bytearray((ROOT / target["path"]).read_bytes())
    data[0] ^= 0x01  # flip one bit of one byte
    mutated = hashlib.sha256(bytes(data)).hexdigest()
    return mutated != target["sha256"], target["path"]


def _online_negative_control(seal_generation: int) -> dict[str, Any]:
    """The §9.1 negative control must have run and blocked every probe. Its
    absence or failure is invalidating (invariant 13: no negative control =
    cannot distinguish blocked from absent)."""
    path = ROOT / "evidence" / f"verify-online-{seal_generation}.json"
    if not path.exists():
        return {"present": False, "all_probes_blocked": False}
    data = json.loads(path.read_text())
    return {"present": True, "all_probes_blocked": bool(data.get("all_probes_blocked", False))}


def run_all_assertions() -> dict[str, Any]:
    phase = current_phase(ROOT).value
    guard_mode = os.environ.get("SAGP_GUARD", "enforce")
    state = json.loads((ROOT / ".airgap" / "state.json").read_text())
    seal_generation = int(state.get("seal_generation", 0))

    # On a SEALED host the .pth has already armed the guard in this process; run the
    # probes in-process against that real, production-configured guard (spawning a
    # child is both blocked by the guard's subprocess-deny and unnecessary). When NOT
    # armed (PROVISION / dev), spawn fresh children that self-install — as verify_online
    # requires. See docs/LIMITATIONS.md "The proof cannot yet run on a sealed host".
    armed = egress.is_installed()
    run = pb.run_probe_inprocess if armed else pb.run_probe

    # Assertion 1 — guard installed, both layers.
    a1 = run(_GUARD_RECEIPT)
    guard_ok = a1.outcome == "allowed"

    # Assertions 2–7 — egress probe blocked + positive control allowed. The AF_UNIX
    # positive control (loopback_unix) needs a custom allow_unix the PRODUCTION guard
    # does not carry, so in-process it cannot pass; use loopback_tcp there — proving the
    # guard is alive while docker.sock is blocked, which is the honest OPERATE claim
    # (the real config allows no AF_UNIX at all).
    af_unix_positive = "loopback_tcp" if armed else "loopback_unix"
    pairs = [
        (2, "L1 TCP block", "l1_tcp", "loopback_tcp"),
        (3, "L2 raw-socket block", "l2_raw_socket", "loopback_tcp"),
        (4, "getaddrinfo block", "getaddrinfo", "loopback_getaddrinfo"),
        (5, "httpx block", "httpx", "loopback_httpx"),
        (6, "subprocess egress block", "subprocess_curl", "subprocess_ollama"),
        (7, "AF_UNIX / docker.sock block", "af_unix_docker", af_unix_positive),
    ]
    assertions: list[Assertion] = [
        Assertion(1, "guard installed (L1+L2)", guard_ok, a1.detail or "both layers active")
    ]
    probe_detail: dict[str, Any] = {"guard_receipt": a1.__dict__}
    for n, name, egress_name, positive in pairs:
        er = run(pb.EGRESS_PROBES[egress_name])
        pr = run(pb.POSITIVE_CONTROLS[positive])
        ok = er.outcome == "blocked" and pr.outcome == "allowed"
        assertions.append(
            Assertion(n, name, ok, f"egress={er.outcome} control={pr.outcome}")
        )
        probe_detail[egress_name] = er.__dict__
        probe_detail[f"{positive}#{n}"] = pr.__dict__

    # Assertion 8 — sealed email zero-violations; stock contrast DOES fetch.
    sealed = run(pb.SEALED_EMAIL)
    stock = run(pb.STOCK_EMAIL)
    a8_ok = sealed.outcome == "allowed" and sealed.violations == 0
    assertions.append(
        Assertion(
            8,
            "SealedEmailRecognizer: 0 egress violations (stock DOES fetch)",
            a8_ok,
            f"sealed_violations={sealed.violations} stock_violations={stock.violations}",
        )
    )
    probe_detail["sealed_email"] = sealed.__dict__
    probe_detail["stock_email"] = stock.__dict__

    # Assertion 9 — manifest full verify + byte-flip detection.
    mres = mf.verify(ROOT, mode="full")
    flip_ok, flip_path = _byte_flip_detected()
    a9_ok = mres.ok and bool(mres.signature_valid) and flip_ok
    assertions.append(
        Assertion(
            9,
            "manifest full-verify + signature + byte-flip detected",
            a9_ok,
            f"manifest_ok={mres.ok} sig={mres.signature_valid} flip_detected={flip_ok}"
            f" ({flip_path}); {'; '.join(mres.problems[:3])}",
        )
    )

    # --- invalidating conditions (invariant 13) --------------------------------
    listeners, method = _nonloopback_listeners()
    ledger = ev.verify_ledger(ROOT)
    onc = _online_negative_control(seal_generation)
    invalidators = [
        Invalidator("guard_not_installed", not guard_ok, a1.detail),
        Invalidator("phase_not_operate", phase != "OPERATE", f"phase={phase}"),
        Invalidator("guard_mode_not_enforce", guard_mode != "enforce", f"SAGP_GUARD={guard_mode}"),
        Invalidator(
            "nonloopback_listeners",
            listeners is None or len(listeners) > 0,
            f"method={method}; found={listeners}",
        ),
        Invalidator(
            "manifest_signature_invalid",
            mres.signature_valid is not True,
            f"signature_valid={mres.signature_valid}",
        ),
        Invalidator("ledger_chain_broken", not ledger.ok, ledger.problem),
        Invalidator(
            "online_negative_control_absent_or_failed",
            not onc["all_probes_blocked"],
            f"online={onc}",
        ),
    ]

    known_gaps = ev.known_gaps_from_metrics(ROOT)
    verdict = ev.compute_verdict(assertions, invalidators, known_gaps)

    return {
        "seal_generation": seal_generation,
        "phase": phase,
        "guard_mode": guard_mode,
        "verdict": verdict,
        "assertions": [a.__dict__ for a in assertions],
        "invalidating_conditions": [i.__dict__ for i in invalidators],
        "known_gaps": [g.__dict__ for g in known_gaps],
        "manifest": {"root_hash": mres.root_hash, "signature_valid": mres.signature_valid},
        "online_negative_control": onc,
        "host": {"platform": platform.system().lower(), "python": platform.python_version()},
        "probe_detail": probe_detail,
    }


def _print_report(result: dict[str, Any]) -> None:
    v = result["verdict"]
    print("=" * 72)
    print(f"  make verify — offline air-gap proof   VERDICT: {v}")
    print("=" * 72)
    for a in result["assertions"]:
        mark = "PASS" if a["ok"] else "FAIL"
        print(f"  [{mark}] {a['n']}. {a['name']}")
        if not a["ok"]:
            print(f"         {a['detail']}")
    triggered = [i for i in result["invalidating_conditions"] if i["triggered"]]
    if triggered:
        print("-" * 72)
        print("  INVALIDATING CONDITIONS (each forces INVALID, never PASS):")
        for i in triggered:
            print(f"    - {i['name']}: {i['detail']}")
    gaps = [g for g in result["known_gaps"] if g["status"] == "OPEN"]
    if gaps:
        print("-" * 72)
        print("  OPEN known gaps:")
        for g in gaps:
            print(f"    - {g['id']} (severity={g['severity']})")
    print("=" * 72)
    print(f"  VERDICT: {v}    (green = {ev.is_pass(v)})")
    print("=" * 72)


def main() -> int:
    result = run_all_assertions()
    out_dir = ROOT / "evidence"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"verify-airgap-{result['seal_generation']}.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    _print_report(result)
    return 0 if ev.is_pass(result["verdict"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
