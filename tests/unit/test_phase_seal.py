"""The seal/unseal one-way door and its invariant-13 gating (tmp roots only —
never the real host)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sagp.netguard import phase


def _state(root: Path, **kw: object) -> None:
    base = {"phase": "PROVISION", "seal_generation": 0, "unseal_history": []}
    base.update(kw)
    (root / ".airgap").mkdir(parents=True, exist_ok=True)
    (root / ".airgap" / "state.json").write_text(json.dumps(base))


def test_seal_refused_without_preconditions(tmp_path: Path) -> None:
    _state(tmp_path)  # PROVISION, but no manifest and no verify-online
    problems = phase.seal_preconditions(tmp_path)
    assert problems  # manifest + online-control unmet
    with pytest.raises(phase.SealError):
        phase.seal(tmp_path)
    assert phase.current_phase(tmp_path) is phase.Phase.PROVISION  # unchanged


def test_seal_refused_when_not_provision(tmp_path: Path) -> None:
    _state(tmp_path, phase="OPERATE")
    problems = phase.seal_preconditions(tmp_path)
    assert any("must be PROVISION" in p for p in problems)


def test_seal_transition_when_preconditions_met(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _state(tmp_path)
    monkeypatch.setattr(phase, "seal_preconditions", lambda root=None: [])  # gate satisfied
    state = phase.seal(tmp_path)
    assert state["phase"] == "OPERATE"
    assert state["seal_generation"] == 1  # incremented on seal
    assert "sealed_at" in state


def test_unseal_returns_to_provision_and_logs(tmp_path: Path) -> None:
    _state(tmp_path, phase="OPERATE", seal_generation=1)
    state = phase.unseal("add pypdf 6.15.0", tmp_path)
    assert state["phase"] == "PROVISION"
    assert state["seal_generation"] == 1  # NOT decremented
    assert len(state["unseal_history"]) == 1
    assert state["unseal_history"][0]["reason"] == "add pypdf 6.15.0"


def test_unseal_requires_a_reason(tmp_path: Path) -> None:
    _state(tmp_path, phase="OPERATE", seal_generation=1)
    with pytest.raises(phase.SealError, match="REASON"):
        phase.unseal("   ", tmp_path)
    assert phase.current_phase(tmp_path) is phase.Phase.OPERATE  # unchanged


def test_unseal_refused_when_not_operate(tmp_path: Path) -> None:
    _state(tmp_path, phase="PROVISION")
    with pytest.raises(phase.SealError, match="must be OPERATE"):
        phase.unseal("reason", tmp_path)


def test_latest_online_control_picks_highest_generation(tmp_path: Path) -> None:
    ev = tmp_path / "evidence"
    ev.mkdir()
    (ev / "verify-online-0.json").write_text(json.dumps({"all_probes_blocked": True}))
    (ev / "verify-online-2.json").write_text(json.dumps({"all_probes_blocked": False}))
    (ev / "verify-online-1.json").write_text(json.dumps({"all_probes_blocked": True}))
    gen, blocked = phase._latest_online_control(tmp_path)
    assert gen == 2 and blocked is False  # highest gen wins, even if it failed


def test_seal_gate_fails_when_latest_control_did_not_block(tmp_path: Path) -> None:
    _state(tmp_path)
    ev = tmp_path / "evidence"
    ev.mkdir()
    (ev / "verify-online-0.json").write_text(json.dumps({"all_probes_blocked": False}))
    problems = phase.seal_preconditions(tmp_path)
    assert any("did not block" in p for p in problems)
