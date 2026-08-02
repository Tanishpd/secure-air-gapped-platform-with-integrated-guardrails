"""Manifest verification.

``verify(mode="full")`` recomputes the sha256 of every file listed in
``models/MANIFEST.json``, checks the root hash, checks the Ed25519 signature
against the committed public key, and fails on any unmanifested file under
``models/`` (excluding the manifest sidecars and the parity-only safetensors).

``full`` is the only mode used at boot: ``quick`` skips file interiors and is an
invalidating condition for any PASS verdict (invariant 13 / forbidden idea).
Run as a CLI for ``make verify-manifest``:

    python -m sagp.netguard.manifest            # full verify, exit 1 on any break
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

MANIFEST_REL = Path("models") / "MANIFEST.json"
PUBKEY_REL = Path(".airgap") / "keys" / "manifest_ed25519.pub"
SIDECAR_NAMES = {"MANIFEST.json", "MANIFEST.json.sha256", "MANIFEST.json.sig", "README.md"}
EXCLUDE_SUFFIXES = ("model.safetensors",)
# serve.log is runtime output; the rest are content-irrelevant OS/Finder cruft that
# would otherwise fail the seal on macOS (rehearsal 2026-08-02: .DS_Store under models/
# refused `make seal`). Named exactly — never a wildcard — so a planted artifact still
# fails the unmanifested-file check (invariant 4).
EXCLUDE_NAMES = {"serve.log", ".DS_Store", ".localized", "Thumbs.db", "desktop.ini"}


@dataclass
class VerifyResult:
    ok: bool
    root_hash: str | None = None
    signature_valid: bool | None = None
    problems: list[str] = field(default_factory=list)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _managed_files(root: Path) -> set[str]:
    out: set[str] = set()
    base = root / "models"
    if not base.exists():
        return out
    for p in sorted(base.rglob("*")):
        if not p.is_file():
            continue
        if p.name in SIDECAR_NAMES or p.name in EXCLUDE_NAMES or p.name.endswith(EXCLUDE_SUFFIXES):
            continue
        out.add(p.relative_to(root).as_posix())
    return out


def verify(root: Path | None = None, mode: str = "full") -> VerifyResult:
    root = root or Path.cwd()
    if mode != "full":
        return VerifyResult(
            ok=False, problems=[f"mode={mode!r} is invalidating; only 'full' is a PASS"]
        )

    manifest_path = root / MANIFEST_REL
    if not manifest_path.exists():
        return VerifyResult(ok=False, problems=[f"missing {MANIFEST_REL}"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    problems: list[str] = []
    listed = set()
    lines = []
    for entry in manifest.get("files", []):
        rel = entry["path"]
        listed.add(rel)
        p = root / rel
        if not p.exists():
            problems.append(f"missing file: {rel}")
            continue
        digest = _sha256(p)
        if digest != entry["sha256"]:
            problems.append(f"hash mismatch: {rel}")
            continue
        if p.stat().st_size != entry.get("size", p.stat().st_size):
            problems.append(f"size mismatch: {rel}")
        lines.append(f"{rel}\0{digest}")

    # Unmanifested files under models/ are a failure.
    for rel in _managed_files(root) - listed:
        problems.append(f"unmanifested file under models/: {rel}")

    recomputed = hashlib.sha256(("\n".join(sorted(lines)) + "\n").encode()).hexdigest()
    root_hash = manifest.get("root_hash")
    if recomputed != root_hash:
        problems.append(
            f"root_hash mismatch: recomputed {recomputed[:16]}… != {str(root_hash)[:16]}…"
        )

    sig_valid: bool | None = None
    sig = manifest.get("signature")
    pub = root / PUBKEY_REL
    if sig and root_hash and pub.exists():
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            pk = serialization.load_pem_public_key(pub.read_bytes())
            if not isinstance(pk, Ed25519PublicKey):
                problems.append(f"public key is not Ed25519 ({type(pk).__name__})")
            else:
                try:
                    pk.verify(bytes.fromhex(sig["sig"]), root_hash.encode())
                    sig_valid = True
                except InvalidSignature:
                    sig_valid = False
                    problems.append("signature INVALID")
        except Exception as exc:  # noqa: BLE001
            problems.append(f"signature check error: {exc}")
    elif sig:
        problems.append("signature present but public key missing")

    return VerifyResult(
        ok=not problems, root_hash=root_hash, signature_valid=sig_valid, problems=problems
    )


def _main() -> int:
    res = verify(mode="full")
    if res.ok:
        rh = (res.root_hash or "")[:16]
        print(f"MANIFEST OK — root_hash={rh}… signature_valid={res.signature_valid}")
        return 0
    print("MANIFEST FAILED:", file=sys.stderr)
    for p in res.problems:
        print(f"  - {p}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(_main())
