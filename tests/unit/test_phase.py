"""Lifecycle state machine: transitions and the OPERATE refusal rule."""

from __future__ import annotations

from pathlib import Path

import pytest

from sagp.netguard import phase


def test_default_phase_is_bootstrap(tmp_path: Path) -> None:
    assert phase.current_phase(tmp_path) is phase.Phase.BOOTSTRAP


def test_init_then_to_provision(tmp_path: Path) -> None:
    phase.init_state(tmp_path)
    assert phase.current_phase(tmp_path) is phase.Phase.BOOTSTRAP
    phase.to_provision(tmp_path)
    assert phase.current_phase(tmp_path) is phase.Phase.PROVISION
    assert (tmp_path / ".airgap" / "state.json").exists()


def test_to_provision_is_idempotent(tmp_path: Path) -> None:
    phase.to_provision(tmp_path)
    phase.to_provision(tmp_path)
    assert phase.current_phase(tmp_path) is phase.Phase.PROVISION


def test_operate_refuses_provisioning(tmp_path: Path) -> None:
    # Simulate a sealed host.
    phase._write_state({"phase": "OPERATE", "seal_generation": 1}, tmp_path)
    with pytest.raises(SystemExit) as ei:
        phase.require_provisionable(tmp_path)
    assert ei.value.code == 2
    with pytest.raises(SystemExit):
        phase.to_provision(tmp_path)


def test_corrupt_state_falls_back_to_bootstrap(tmp_path: Path) -> None:
    p = tmp_path / ".airgap" / "state.json"
    p.parent.mkdir(parents=True)
    p.write_text("{not json", encoding="utf-8")
    assert phase.current_phase(tmp_path) is phase.Phase.BOOTSTRAP
