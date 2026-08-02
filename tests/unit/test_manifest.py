"""Manifest verification: clean pass, tamper detection, quick-mode is invalidating."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from sagp.netguard import manifest


def _write_manifest(root: Path, files: dict[str, bytes]) -> None:
    models = root / "models"
    models.mkdir(parents=True, exist_ok=True)
    entries = []
    lines = []
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        entries.append({"path": rel, "sha256": digest, "size": len(data)})
        lines.append(f"{rel}\0{digest}")
    root_hash = hashlib.sha256(("\n".join(sorted(lines)) + "\n").encode()).hexdigest()
    (models / "MANIFEST.json").write_text(
        json.dumps({"manifest_version": 1, "files": entries, "root_hash": root_hash})
    )


def test_clean_manifest_passes(tmp_path: Path) -> None:
    _write_manifest(tmp_path, {"models/hf/a.txt": b"hello", "models/hf/b.bin": b"\x00\x01"})
    res = manifest.verify(tmp_path, mode="full")
    assert res.ok, res.problems
    assert res.signature_valid is None  # unsigned fixture


def test_tamper_is_detected(tmp_path: Path) -> None:
    _write_manifest(tmp_path, {"models/hf/a.txt": b"hello"})
    (tmp_path / "models/hf/a.txt").write_bytes(b"hell0")  # flip a byte
    res = manifest.verify(tmp_path, mode="full")
    assert not res.ok
    assert any("hash mismatch" in p for p in res.problems)


def test_unmanifested_file_is_detected(tmp_path: Path) -> None:
    _write_manifest(tmp_path, {"models/hf/a.txt": b"hello"})
    (tmp_path / "models/hf/sneaky.bin").write_bytes(b"surprise")
    res = manifest.verify(tmp_path, mode="full")
    assert not res.ok
    assert any("unmanifested" in p for p in res.problems)


def test_quick_mode_is_invalidating(tmp_path: Path) -> None:
    _write_manifest(tmp_path, {"models/hf/a.txt": b"hello"})
    res = manifest.verify(tmp_path, mode="quick")
    assert not res.ok
    assert any("invalidating" in p for p in res.problems)


def test_safetensors_excluded_from_unmanifested_check(tmp_path: Path) -> None:
    _write_manifest(tmp_path, {"models/hf/a.txt": b"hello"})
    # A parity-only safetensors is not manifested but must not trip the check.
    (tmp_path / "models/hf/model.safetensors").write_bytes(b"weights")
    res = manifest.verify(tmp_path, mode="full")
    assert res.ok, res.problems


def test_os_cruft_excluded_from_unmanifested_check(tmp_path: Path) -> None:
    # macOS Finder scatters .DS_Store; it must not fail the seal (rehearsal 2026-08-02).
    _write_manifest(tmp_path, {"models/hf/a.txt": b"hello"})
    (tmp_path / "models/.DS_Store").write_bytes(b"\x00\x00\x00")
    (tmp_path / "models/hf/.DS_Store").write_bytes(b"\x00\x00\x00")
    res = manifest.verify(tmp_path, mode="full")
    assert res.ok, res.problems


def test_unmanifested_check_still_catches_a_planted_dotfile(tmp_path: Path) -> None:
    # The OS-cruft exclusion is by exact name, not a wildcard: any OTHER unexpected
    # file (even a dotfile) still fails — the exclusion is not a hole in invariant 4.
    _write_manifest(tmp_path, {"models/hf/a.txt": b"hello"})
    (tmp_path / "models/.hidden_payload").write_bytes(b"surprise")
    res = manifest.verify(tmp_path, mode="full")
    assert not res.ok
    assert any("unmanifested" in p for p in res.problems)
