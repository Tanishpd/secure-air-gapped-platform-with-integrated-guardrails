#!/usr/bin/env python
"""``make evidence`` — render + sign the ``EVIDENCE-<gen>-<utc>`` report and append
one link to the hash-chained ledger (BLUEPRINT §9).

Reads the intermediate ``evidence/verify-airgap-<gen>.json`` that ``make verify``
wrote (so the signature covers the ACTUAL verify output, never a re-run that might
differ), assembles the report via ``netguard.evidence.build_report`` (which binds
and signs its ``root_hash`` with the host Ed25519 key), writes both ``.json`` and a
human ``.md``, and appends to ``evidence/ledger.jsonl``.

The signature is self-signed on the host it attests to: tamper-EVIDENT, not
provenance. The ledger head must be exported off-box to mean anything
(OPERATIONS.md). Run ``make verify`` first.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sagp.netguard import evidence as ev  # noqa: E402
from sagp.netguard.evidence import Assertion, Invalidator, KnownGap  # noqa: E402


def _render_md(report: dict[str, Any]) -> str:
    v = report["verdict"]
    lines = [
        f"# EVIDENCE — air-gap demonstration (generation {report['seal_generation']})",
        "",
        f"- **Verdict:** `{v}`  (green = {ev.is_pass(v)})",
        f"- **Generated:** {report['generated_ts']} (local clock — no offline TSA)",
        f"- **Phase:** {report['phase']}  ·  **Guard mode:** {report['guard_mode']}",
        f"- **Manifest root_hash:** `{report['manifest'].get('root_hash')}`"
        f"  ·  signature valid: {report['manifest'].get('signature_valid')}",
        f"- **root_hash:** `{report.get('root_hash')}`",
    ]
    sig = report.get("signature")
    if sig:
        lines.append(f"- **Signature:** ed25519 key `{sig['key_id']}` (self-signed)")
    lines += ["", "## Assertions", "", "| # | Assertion | Result |", "|---|---|---|"]
    for a in report["assertions"]:
        lines.append(f"| {a['n']} | {a['name']} | {'PASS' if a['ok'] else 'FAIL'} |")
    triggered = [i for i in report["invalidating_conditions"] if i["triggered"]]
    lines += ["", "## Invalidating conditions (invariant 13)", ""]
    if triggered:
        for i in triggered:
            lines.append(f"- **{i['name']}** — {i['detail']}")
    else:
        lines.append("- none triggered")
    onc = report["online_negative_control"]
    lines += [
        "",
        "## Negative control (verify-online)",
        "",
        f"- present: {onc.get('present')}  ·  all probes blocked: {onc.get('all_probes_blocked')}",
    ]
    gaps = [g for g in report["known_gaps"] if g["status"] == "OPEN"]
    lines += ["", "## Open known gaps", ""]
    lines += (
        [f"- {g['id']} (severity {g['severity']})" for g in gaps] if gaps else ["- none"]
    )
    lines += [
        "",
        "---",
        "",
        "*Self-signed on the host it attests to. Tamper-evident, not provenance; "
        "not a certification. See LIMITATIONS.md.*",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    state = json.loads((ROOT / ".airgap" / "state.json").read_text())
    gen = int(state.get("seal_generation", 0))
    intermediate = ROOT / "evidence" / f"verify-airgap-{gen}.json"
    if not intermediate.exists():
        print(f"ERROR: {intermediate.relative_to(ROOT)} not found — run `make verify` first.")
        return 1
    r = json.loads(intermediate.read_text())

    report = ev.build_report(
        seal_generation=gen,
        phase=r["phase"],
        guard_mode=r["guard_mode"],
        verdict=r["verdict"],
        assertions=[Assertion(**a) for a in r["assertions"]],
        invalidators=[Invalidator(**i) for i in r["invalidating_conditions"]],
        known_gaps=[KnownGap(**g) for g in r["known_gaps"]],
        manifest=r["manifest"],
        online_negative_control=r["online_negative_control"],
        host=r["host"],
        root=ROOT,
    )

    stamp = report["generated_ts"].replace(":", "").replace("-", "")
    base = ROOT / "evidence" / f"EVIDENCE-{gen}-{stamp}"
    base.parent.mkdir(parents=True, exist_ok=True)
    base.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    base.with_suffix(".md").write_text(_render_md(report), encoding="utf-8")

    link = ev.append_ledger(
        seal_generation=gen,
        evidence_root_hash=report["root_hash"],
        verdict=report["verdict"],
        root=ROOT,
    )

    print(f"wrote {base.with_suffix('.json').relative_to(ROOT)} (+ .md)")
    print(f"verdict={report['verdict']}  root_hash={report['root_hash'][:16]}…")
    print(f"ledger head={link['chain_digest'][:16]}…  (export it off-box — OPERATIONS.md)")
    # Evidence is written for any verdict, but the process exit reflects it.
    return 0 if ev.is_pass(report["verdict"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
