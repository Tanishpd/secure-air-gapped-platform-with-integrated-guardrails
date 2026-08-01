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


class SealError(Exception):
    """A seal precondition (invariant 13) is unmet; refuse to seal. Not a SagpError."""


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


def _latest_online_control(root: Path) -> tuple[int, bool] | None:
    """The most recent ``evidence/verify-online-<gen>.json``: (generation, all_blocked).

    Keyed on "the most recent demonstration that the guard blocks with internet
    present", so the seal gate is immune to the seal-vs-file generation off-by-one
    (the generation increments at seal; the control was written pre-seal)."""
    ev_dir = (root or Path.cwd()) / "evidence"
    best: tuple[int, bool] | None = None
    if not ev_dir.exists():
        return None
    for p in ev_dir.glob("verify-online-*.json"):
        try:
            gen = int(p.stem.rsplit("-", 1)[1])
            data = json.loads(p.read_text(encoding="utf-8"))
        except (ValueError, OSError, json.JSONDecodeError):
            continue
        if best is None or gen > best[0]:
            best = (gen, bool(data.get("all_probes_blocked", False)))
    return best


def seal_preconditions(root: Path | None = None) -> list[str]:
    """Return the unmet seal preconditions (invariant 13). Empty list == sealable.

    Refuses to seal unless the manifest verifies in FULL mode with a valid
    signature AND a green online negative control exists — because a seal without
    a demonstrated-blocking-while-online control cannot distinguish a real air gap
    from a merely-absent network.
    """
    from sagp.netguard import manifest as mf

    root = root or Path.cwd()
    problems: list[str] = []
    if current_phase(root) is not Phase.PROVISION:
        problems.append(f"phase is {current_phase(root).value}, must be PROVISION to seal")
    res = mf.verify(root, mode="full")
    if not res.ok:
        problems.append(f"manifest full-verify failed: {'; '.join(res.problems[:3])}")
    elif res.signature_valid is not True:
        problems.append(f"manifest signature not valid (signature_valid={res.signature_valid})")
    control = _latest_online_control(root)
    if control is None:
        problems.append("no evidence/verify-online-<gen>.json — run `make verify-online` online")
    elif not control[1]:
        problems.append(f"online negative control (gen {control[0]}) did not block every probe")
    return problems


def seal(root: Path | None = None) -> State:
    """PROVISION -> OPERATE. Increments ``seal_generation``. Raises ``SealError``
    if any precondition is unmet (invariant 13); ``make seal`` writes .env.sealed
    and installs the .pth guard around this transition."""
    root = root or Path.cwd()
    problems = seal_preconditions(root)
    if problems:
        raise SealError("cannot seal:\n  - " + "\n  - ".join(problems))
    state = read_state(root)
    gen = state.get("seal_generation", 0)
    state["phase"] = Phase.OPERATE.value
    state["seal_generation"] = (gen if isinstance(gen, int) else 0) + 1
    state["sealed_at"] = _now()
    _write_state(state, root)
    return state


def unseal(reason: str, root: Path | None = None) -> State:
    """OPERATE -> PROVISION, one controlled reconnection. Requires a non-empty
    ``reason`` (refuses otherwise) and appends it to ``unseal_history``. Does NOT
    decrement ``seal_generation`` — the next seal mints a fresh one."""
    if not reason or not reason.strip():
        raise SealError("unseal requires a non-empty REASON=")
    root = root or Path.cwd()
    if current_phase(root) is not Phase.OPERATE:
        raise SealError(f"phase is {current_phase(root).value}, must be OPERATE to unseal")
    state = read_state(root)
    history = state.get("unseal_history")
    if not isinstance(history, list):
        history = []
    history.append(
        {"reason": reason.strip(), "at": _now(), "from_generation": state.get("seal_generation", 0)}
    )
    state["unseal_history"] = history
    state["phase"] = Phase.PROVISION.value
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
    if cmd == "seal-preconditions":
        problems = seal_preconditions()
        if problems:
            sys.stderr.write("NOT SEALABLE:\n  - " + "\n  - ".join(problems) + "\n")
            return 1
        print("OK: all seal preconditions met")
        return 0
    if cmd == "seal":
        try:
            state = seal()
        except SealError as exc:
            sys.stderr.write(f"REFUSED: {exc}\n")
            return 1
        print(f"SEALED: phase=OPERATE seal_generation={state['seal_generation']}")
        return 0
    if cmd == "unseal":
        import os

        reason = argv[2] if len(argv) > 2 else os.environ.get("REASON", "")
        try:
            state = unseal(reason)
        except SealError as exc:
            sys.stderr.write(f"REFUSED: {exc}\n")
            return 1
        print(f"UNSEALED: phase=PROVISION seal_generation={state['seal_generation']}")
        return 0
    if cmd == "status":
        st = read_state()
        hist = st.get("unseal_history", [])
        print(
            json.dumps(
                {
                    "phase": st.get("phase"),
                    "seal_generation": st.get("seal_generation", 0),
                    "unseal_count": len(hist) if isinstance(hist, list) else 0,
                }
            )
        )
        return 0
    sys.stderr.write(f"unknown command: {cmd}\n")
    return 64


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
