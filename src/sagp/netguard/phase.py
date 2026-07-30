"""Lifecycle state machine: BOOTSTRAP -> PROVISION -> OPERATE.

State lives in ``.airgap/state.json``. This module owns every transition and the
refusal rules, and **every Make target that could touch the network imports it**
(CLAUDE.md §5). Stdlib only, so it runs identically under ``.venv`` and
``.venv-provision``.

Refusal rules enforced here:

* any ``provision*`` step **exits 2 when ``phase == OPERATE``** — the sealed host
  is past a one-way door; the correct move is ``make unseal REASON="…"``, not a
  workaround.
* ``seal`` requires a green online negative control (checked by its own target).
* ``unseal`` requires a ``REASON`` and appends to ``unseal_history``.

Run as a CLI for Make targets:

    python -m sagp.netguard.phase current       # print the phase
    python -m sagp.netguard.phase require-provision   # exit 2 if OPERATE
    python -m sagp.netguard.phase init          # create BOOTSTRAP state if absent
    python -m sagp.netguard.phase to-provision  # BOOTSTRAP/PROVISION -> PROVISION
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

STATE_REL = Path(".airgap") / "state.json"

State = dict[str, object]


class Phase(StrEnum):
    BOOTSTRAP = "BOOTSTRAP"
    PROVISION = "PROVISION"
    OPERATE = "OPERATE"


def _state_path(root: Path | None = None) -> Path:
    return (root or Path.cwd()) / STATE_REL


def _default_state() -> State:
    return {"phase": Phase.BOOTSTRAP.value, "seal_generation": 0, "unseal_history": []}


def read_state(root: Path | None = None) -> State:
    """Return the state dict, defaulting to a fresh BOOTSTRAP if absent/unreadable.

    Unreadable/missing state is treated as BOOTSTRAP for phase logic, but the
    ``.pth`` guard treats the same condition as *enforce* — never trust an
    absent file to mean "open" (BLUEPRINT §6).
    """
    path = _state_path(root)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return _default_state()
    return data if isinstance(data, dict) else _default_state()


def current_phase(root: Path | None = None) -> Phase:
    return Phase(str(read_state(root).get("phase", Phase.BOOTSTRAP.value)))


def _write_state(state: State, root: Path | None = None) -> None:
    path = _state_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def init_state(root: Path | None = None) -> State:
    """Create a BOOTSTRAP state file if none exists; return the current state."""
    path = _state_path(root)
    if not path.exists():
        state = _default_state()
        _write_state(state, root)
        return state
    return read_state(root)


def require_provisionable(root: Path | None = None) -> None:
    """Exit 2 if the host is sealed (phase == OPERATE).

    Not a bug and not a permissions problem: the sealed host is past the one-way
    door. Add the artifact to artifacts.lock and `make unseal REASON="…"` first.
    """
    phase = current_phase(root)
    if phase is Phase.OPERATE:
        sys.stderr.write(
            "REFUSED: phase is OPERATE (sealed). Provisioning is a one-way door.\n"
            'Run `make unseal REASON="…"` to reconnect, then re-provision.\n'
        )
        raise SystemExit(2)


def to_provision(root: Path | None = None) -> State:
    """Move BOOTSTRAP -> PROVISION (idempotent). Refuses from OPERATE."""
    require_provisionable(root)
    state = init_state(root)
    if state.get("phase") != Phase.PROVISION.value:
        state["phase"] = Phase.PROVISION.value
        state["provisioned_at"] = _now()
        _write_state(state, root)
    return state


def _main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "current"
    if cmd == "current":
        print(current_phase().value)
        return 0
    if cmd == "init":
        print(init_state()["phase"])
        return 0
    if cmd == "require-provision":
        require_provisionable()
        print(f"OK: phase is {current_phase().value}, provisioning allowed")
        return 0
    if cmd == "to-provision":
        print(to_provision()["phase"])
        return 0
    sys.stderr.write(f"unknown command: {cmd}\n")
    return 64


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
