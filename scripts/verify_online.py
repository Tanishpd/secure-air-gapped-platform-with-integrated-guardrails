#!/usr/bin/env python
"""``make verify-online`` — the NEGATIVE CONTROL (BLUEPRINT §9.1).

The one piece of evidence that distinguishes *blocked* from *absent*. Run during
PROVISION, while the host demonstrably has internet:

1. **Baseline** (guard NOT installed): resolve ``huggingface.co`` and complete a
   TCP handshake to ``1.1.1.1:443``. These MUST succeed — if they don't, the host
   has no internet and the whole air-gap claim is ``INVALID``, because a later
   "blocked" would be indistinguishable from "the network was never there".
2. **Enforce** (guard installed): re-run the identical probes. Each MUST raise
   ``EgressViolation``.

Writes ``evidence/verify-online-<gen>.json`` with both timings and
``all_probes_blocked``. ``make seal`` refuses to proceed without it.
"""

from __future__ import annotations

import json
import platform
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sagp.netguard import evidence as ev  # noqa: E402
from sagp.netguard import probes as pb  # noqa: E402

# The identical probe bodies, run first WITHOUT then WITH the guard.
_DNS = "socket.getaddrinfo('huggingface.co', 443)"
_TCP = "socket.create_connection(('1.1.1.1', 443), timeout=5).close()"

BASELINE = [
    pb.Probe("baseline_dns", _DNS, install=""),  # empty install -> unguarded
    pb.Probe("baseline_tcp", _TCP, install=""),
]
ENFORCED = [
    pb.Probe("enforced_dns", _DNS),
    pb.Probe("enforced_tcp", _TCP),
]


def main() -> int:
    state = json.loads((ROOT / ".airgap" / "state.json").read_text())
    seal_generation = int(state.get("seal_generation", 0))

    baseline = [pb.run_probe(p) for p in BASELINE]
    enforced = [pb.run_probe(p) for p in ENFORCED]

    host_has_internet = all(r.outcome == "allowed" for r in baseline)
    all_probes_blocked = all(r.outcome == "blocked" for r in enforced)
    verdict = ev.PASS if (host_has_internet and all_probes_blocked) else ev.INVALID

    report: dict[str, Any] = {
        "generated_ts": ev.now_utc(),
        "seal_generation": seal_generation,
        "host": {"platform": platform.system().lower(), "python": platform.python_version()},
        "baseline": [r.__dict__ for r in baseline],
        "enforced": [r.__dict__ for r in enforced],
        "host_has_internet": host_has_internet,
        "all_probes_blocked": all_probes_blocked,
        "verdict": verdict,
    }
    out = ROOT / "evidence" / f"verify-online-{seal_generation}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("=" * 72)
    print(f"  make verify-online — negative control   VERDICT: {verdict}")
    print("=" * 72)
    for r in baseline:
        print(f"  baseline  {r.name:14s} {r.outcome:8s} {r.elapsed_ms:8.2f} ms   (want allowed)")
    for r in enforced:
        print(f"  enforced  {r.name:14s} {r.outcome:8s} {r.elapsed_ms:8.2f} ms   (want blocked)")
    print("-" * 72)
    if not host_has_internet:
        print("  INVALID: baseline could not reach the internet — cannot distinguish")
        print("           a blocked probe from an absent network. Reconnect and re-run.")
    elif not all_probes_blocked:
        print("  INVALID: the guard did not block every probe with internet present.")
    else:
        b = baseline[1]
        e = enforced[1]
        print(
            f"  This host completed a TCP handshake to 1.1.1.1:443 in {b.elapsed_ms:.2f} ms "
            f"unguarded;\n  with the guard enforcing, the identical probe raised "
            f"EgressViolation in {e.elapsed_ms:.2f} ms."
        )
    print(f"  wrote {out.relative_to(ROOT)}")
    print("=" * 72)
    return 0 if verdict == ev.PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
