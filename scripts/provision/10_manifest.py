"""10 — hash every provisioned file into MANIFEST.json and sign it (Ed25519).

Schema is the airgap schema (BLUEPRINT §2.7): per-file sha256 + size, a root_hash
over the sorted 'path\\0hex\\n' lines, and a detached signature. The classifier's
model.safetensors is EXCLUDED from the runtime manifest — it exists only for the
07 parity gate. Timestamp is local-clock (no offline TSA; LIMITATIONS item 6).
"""

from __future__ import annotations

import hashlib
import json

from _common import ROOT, log

STEP = "10_manifest"

# Directories whose contents are the sealed runtime artifact set.
INCLUDE_DIRS = ["models"]
# Excluded from the runtime manifest (parity-gate input only, and derived caches).
EXCLUDE_SUFFIXES = ("model.safetensors",)
EXCLUDE_NAMES = {"serve.log"}


def _sha256(path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _iter_files():
    for d in INCLUDE_DIRS:
        base = ROOT / d
        if not base.exists():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            if p.name in EXCLUDE_NAMES or p.name.endswith(EXCLUDE_SUFFIXES):
                continue
            yield p


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    files = []
    lines = []
    for p in _iter_files():
        rel = p.relative_to(ROOT).as_posix()
        digest = _sha256(p)
        files.append({"path": rel, "sha256": digest, "size": p.stat().st_size})
        lines.append(f"{rel}\0{digest}")
    root_hash = hashlib.sha256(("\n".join(sorted(lines)) + "\n").encode()).hexdigest()

    manifest = {
        "manifest_version": 1,
        "generated_ts": _now(),
        "canonicalization": "sha256 over sorted 'path\\0hex' lines joined by \\n, trailing \\n",
        "files": files,
        "root_hash": root_hash,
        "manifest_hash": root_hash,  # alias
    }

    priv = ROOT / ".airgap" / "keys" / "manifest_ed25519"
    sig_hex = None
    key_id = None
    if priv.exists():
        from cryptography.hazmat.primitives import serialization

        sk = serialization.load_pem_private_key(priv.read_bytes(), password=None)
        sig = sk.sign(root_hash.encode())
        sig_hex = sig.hex()
        pub_raw = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        key_id = hashlib.sha256(pub_raw).hexdigest()[:16]
        manifest["signature"] = {"alg": "ed25519", "key_id": key_id, "sig": sig_hex}

    models_dir = ROOT / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    out = models_dir / "MANIFEST.json"
    out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (models_dir / "MANIFEST.json.sha256").write_text(root_hash + "\n", encoding="utf-8")
    if sig_hex:
        (models_dir / "MANIFEST.json.sig").write_text(sig_hex + "\n", encoding="utf-8")

    log(STEP, f"{len(files)} files hashed; root_hash={root_hash[:16]}… key_id={key_id}")
    log(STEP, f"wrote {out.relative_to(ROOT)} (+ .sha256/.sig)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
