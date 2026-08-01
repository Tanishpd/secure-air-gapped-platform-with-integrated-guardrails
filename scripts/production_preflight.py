"""Production-readiness gate — an honest go/no-go, not a rubber stamp.

Checks every readiness criterion this repo CAN check mechanically and prints it with
a status, then lists the gates that require a human action, a credential, or hardware
this process does not have. The verdict is `NOT READY` while any blocking gate is open
— which is the truthful state of an unsealed dev host, and the whole point of a
compliance template that refuses to overclaim (see docs/LIMITATIONS.md).

  make production-preflight     # or: .venv/bin/python scripts/production_preflight.py

Status vocabulary:
  GREEN   automated check passed here, now
  RED     automated check failed — a real, closeable defect
  RUN     an existing gate must be executed (command given); some cannot PASS until sealed
  HUMAN   requires an operator action, credential, or hardware — cannot be automated

Exit 0 only if every automated check is GREEN AND no gate is open. On any RED, or while
any RUN/HUMAN gate remains, exit 1. A green exit here is necessary, never sufficient —
the air-gap PASS still requires the physical seal + disconnect.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_C = {
    "GREEN": "\033[32m",
    "RED": "\033[31m",
    "GAP": "\033[35m",
    "RUN": "\033[33m",
    "HUMAN": "\033[36m",
    "_": "\033[0m",
}


def _line(status: str, gate: str, detail: str) -> str:
    print(f"  [{_C.get(status, '')}{status:<5}{_C['_']}] {gate:<34} {detail}")
    return status


def _automated() -> list[str]:
    """Cheap, static checks. RED = a hard-gate failure (a real defect); GAP = a
    tracked, documented known-gap whose closure needs an external input, not a fix."""
    print("\nAUTOMATED — checkable now:")
    oks: list[str] = []

    # Guardrail metrics against their floors (docs/metrics/latest.json).
    try:
        m = json.loads((ROOT / "docs/metrics/latest.json").read_text())
        inj, floors = m["injection"], m["floors"]
        oks.append(
            _line(
                "GREEN" if inj["headline_recall"] >= floors["injection_headline_recall"] else "RED",
                "injection recall floor",
                f"{inj['headline_recall']} >= {floors['injection_headline_recall']}",
            )
        )
        oks.append(
            _line(
                "GREEN" if inj["precision"] >= floors["injection_precision"] else "RED",
                "injection precision floor",
                f"{inj['precision']} >= {floors['injection_precision']}",
            )
        )
        # The one measured miss. It is a TRACKED, medium-severity known-gap, not a
        # hard-gate failure: recall/PII are the hard gates; precision/FPR are
        # regression-gated targets. Its only fix is a better classifier (H5, gated),
        # so it is GAP, not RED — reported honestly, never waved through as GREEN.
        fpr_ok = inj["benign_fpr"] <= floors["benign_fpr_ceiling"]
        oks.append(
            _line(
                "GREEN" if fpr_ok else "GAP",
                "benign FPR ceiling",
                f"{inj['benign_fpr']} <= {floors['benign_fpr_ceiling']}  "
                f"(tracked known-gap; only closer is a better classifier — H5)",
            )
        )
        pii = m["pii_recall"]["per_type"]
        pfloor = floors["pii_recall"]
        pii_ok = all(pii[t]["recall"] >= pfloor[t] for t in pfloor)
        oks.append(
            _line("GREEN" if pii_ok else "RED", "PII recall floors", "EMAIL/CARD/AADHAAR/PERSON")
        )
        gaps = m.get("known_gaps", [])
        n_high = sum(1 for g in gaps if g.get("severity") == "high" and g.get("status") == "OPEN")
        oks.append(
            _line("GREEN" if n_high == 0 else "RED", "no OPEN high-severity gaps", f"{n_high} open")
        )
    except Exception as exc:  # noqa: BLE001
        oks.append(_line("RED", "metrics", f"could not read latest.json: {exc}"))

    # Signed manifest present (full recompute is the RUN gate below).
    oks.append(
        _line(
            "GREEN" if (ROOT / "models/MANIFEST.json").is_file() else "RED",
            "signed manifest present",
            "models/MANIFEST.json",
        )
    )

    # Thresholds-as-data parse + validate (invariant 12).
    try:
        from sagp.guardrails.entities import load_entities
        from sagp.guardrails.policy import load_policy

        load_policy(ROOT / "config/guardrails.yaml")
        load_entities(ROOT / "config/entities.yaml")
        oks.append(_line("GREEN", "guardrail config valid", "guardrails.yaml + entities.yaml"))
    except Exception as exc:  # noqa: BLE001
        oks.append(_line("RED", "guardrail config valid", str(exc)))

    # Egress guard importable (installed via .pth at boot in every non-PROVISION phase).
    try:
        import sagp.netguard.egress  # noqa: F401

        oks.append(_line("GREEN", "egress guard importable", "sagp.netguard.egress"))
    except Exception as exc:  # noqa: BLE001
        oks.append(_line("RED", "egress guard importable", str(exc)))

    # CI present.
    oks.append(
        _line(
            "GREEN" if (ROOT / ".github/workflows/ci.yml").is_file() else "RED",
            "CI configured",
            ".github/workflows/ci.yml",
        )
    )

    # The online negative control (paired with the offline proof) blocked every probe.
    try:
        vo = sorted((ROOT / "evidence").glob("verify-online-*.json"))
        blocked = vo and json.loads(vo[-1].read_text()).get("all_probes_blocked") is True
        name = vo[-1].name if vo else "missing"
        oks.append(_line("GREEN" if blocked else "RED", "online negative control", name))
    except Exception as exc:  # noqa: BLE001
        oks.append(_line("RED", "online negative control", str(exc)))

    return oks


def _gates_to_run() -> None:
    print("\nRUN — existing gates to execute (some cannot PASS until sealed):")
    _line("RUN", "make lint typecheck test-ci", "code+types+model-free tests (also CI, green)")
    _line("RUN", "make test-all / test-e2e", "full suite w/ real models + Ollama")
    _line("RUN", "make eval", "regenerate + gate metrics vs baseline")
    _line("RUN", "make smoke", "14 numbered end-to-end checks")
    _line("RUN", "make verify", "9 offline air-gap assertions — INVALID until sealed+offline")
    _line("RUN", "make proof", "verify + signed evidence — the PASS this exists for")


def _human_gates() -> None:
    print("\nHUMAN / EXTERNAL — cannot be automated (the real remaining distance):")
    _line("HUMAN", "H1 physical seal + disconnect", "seal → disconnect → make proof (green PASS)")
    _line("HUMAN", "H2 host egress lockdown", "make seal-pf (sudo pf) — covers native code")
    _line("HUMAN", "H3 key custody", "self-signed Ed25519 → HSM/KMS; ledger head off-box")
    _line("HUMAN", "H4 third-party audit", "independent review; a self-audit isn't a pass")
    _line("HUMAN", "H5 close the FPR ceiling", "HF token + Meta licence → eval Prompt-Guard-2")
    _line("HUMAN", "H6 real target + soak", "deployment host + a sustained soak (not a burst)")
    _line("HUMAN", "H7 host hardening", "FileVault on; ulimit -c 0 (core dump leaks vault)")


def main() -> int:
    print("=" * 74)
    print("PRODUCTION-READINESS PREFLIGHT — honest go/no-go")
    print("=" * 74)
    try:
        state = json.loads((ROOT / ".airgap/state.json").read_text())
        print(f"phase: {state['phase']}   seal_generation: {state['seal_generation']}")
    except Exception:  # noqa: BLE001
        print("phase: (state unreadable — guard installs in enforce by default)")

    oks = _automated()
    _gates_to_run()
    _human_gates()

    n_red = oks.count("RED")
    n_gap = oks.count("GAP")
    print("\n" + "=" * 74)
    if n_red:
        print(f"VERDICT: NOT READY — {n_red} hard gate(s) RED (a real defect above; fix first).")
    else:
        print(
            f"VERDICT: NOT READY — hard gates green"
            f"{f', {n_gap} tracked FPR gap (H5)' if n_gap else ''}; RUN + HUMAN gates open."
        )
    print("A green preflight is NECESSARY, never SUFFICIENT: production readiness still")
    print("requires the physical seal + disconnect + `make proof` (H1) and H2–H7. Calling")
    print("it ready before those is the overclaim this template exists to refuse.")
    print("=" * 74)
    return 1  # not ready while any RUN/HUMAN gate is open — which is always, on a dev host


if __name__ == "__main__":
    raise SystemExit(main())
