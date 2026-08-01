#!/usr/bin/env python
"""make unseal REASON="…" — the one controlled reconnection.

OPERATE -> PROVISION. Refuses without a REASON and appends it to
``unseal_history`` in ``.airgap/state.json``. Does NOT decrement
``seal_generation`` — the next ``make seal`` mints a fresh one. The .pth guard
bootstrap is left installed; it is inert in PROVISION (it reads the phase from
state.json and does not arm), so re-provisioning proceeds unguarded as intended.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sagp.netguard.phase import SealError, unseal  # noqa: E402


def main() -> int:
    reason = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("REASON", "")
    try:
        state = unseal(reason, ROOT)
    except SealError as exc:
        sys.stderr.write(f"REFUSED: {exc}\n")
        return 1
    print(
        f"UNSEALED -> PROVISION (seal_generation stays {state['seal_generation']}). "
        "Reconnect, then: make provision && make verify-online && make seal"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
