"""Egress-guard bootstrap, imported by a ``.pth`` in site-packages at seal time.

Because a ``.pth`` line beginning with ``import`` runs at interpreter start —
before any application code — installing the guard here arms it for the whole
process, including anything a stray script does. The mode is derived SOLELY from
``.airgap/state.json`` (never an env var — a typo must not silently disarm the
guard); an unreadable or missing state file is treated as ``enforce``.

This module is installed beside the ``.pth`` at ``make seal`` (M13). It must
never raise: a bootstrap that crashes the interpreter is worse than the risk it
guards, so failures fall through to enforce-and-continue.
"""

from __future__ import annotations


def _phase_from_state() -> str:
    try:
        import json
        from pathlib import Path

        raw = (Path.cwd() / ".airgap" / "state.json").read_text(encoding="utf-8")
        return str(json.loads(raw).get("phase", "OPERATE"))
    except Exception:
        return "OPERATE"  # unreadable/missing -> enforce


def _boot() -> None:
    # In PROVISION the online harness manages egress explicitly; only OPERATE and
    # unknown states arm the guard here. Missing state -> OPERATE -> armed.
    if _phase_from_state() == "PROVISION":
        return
    try:
        from sagp.netguard.egress import install_egress_guard

        install_egress_guard()
    except Exception:
        # Never break the interpreter. (In a real seal the import cannot fail;
        # this only guards a half-installed tree.)
        pass


_boot()
