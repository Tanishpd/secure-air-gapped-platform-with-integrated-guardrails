"""Admission-control gate (backpressure) — bounded in-flight → 503 ServiceBusy."""

from __future__ import annotations

import pytest

from sagp.app.concurrency import AdmissionGate
from sagp.errors import ServiceBusy


def test_admits_up_to_capacity() -> None:
    gate = AdmissionGate(3)
    for _ in range(3):
        gate.acquire()
    assert gate.in_flight == 3


def test_sheds_over_capacity() -> None:
    gate = AdmissionGate(2)
    gate.acquire()
    gate.acquire()
    with pytest.raises(ServiceBusy):
        gate.acquire()  # third is shed
    assert gate.in_flight == 2  # a shed request does not consume a slot


def test_release_frees_a_slot() -> None:
    gate = AdmissionGate(1)
    gate.acquire()
    with pytest.raises(ServiceBusy):
        gate.acquire()
    gate.release()
    gate.acquire()  # freed -> admitted again
    assert gate.in_flight == 1


def test_release_never_goes_negative() -> None:
    gate = AdmissionGate(1)
    gate.release()  # unbalanced release must not underflow
    gate.release()
    assert gate.in_flight == 0
    gate.acquire()
    assert gate.in_flight == 1


def test_service_busy_message_has_no_count() -> None:
    gate = AdmissionGate(0)
    with pytest.raises(ServiceBusy) as ei:
        gate.acquire()
    assert ei.value.status_code == 503 and ei.value.code == "SERVICE_BUSY"
    assert not any(ch.isdigit() for ch in str(ei.value))  # not an abuse oracle
