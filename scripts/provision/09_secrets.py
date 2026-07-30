"""09 — generate the five runtime secrets. Prints names + destinations only.

Writes SAGP_-prefixed secrets into .env (0600) and the Ed25519 keypair into
.airgap/keys/ (private 0600, public 0644 and committed). Idempotent: never
overwrites an existing secret (rotation is a deliberate, separate action —
OPERATIONS §1). A printed secret value would be a defect.
"""

from __future__ import annotations

import secrets as _secrets
import stat

from _common import ROOT, log

STEP = "09_secrets"

ENV_SECRETS = ("SAGP_API_TOKEN", "SAGP_API_TOKEN_REVEAL", "SAGP_AUDIT_HMAC_KEY", "SAGP_PII_PEPPER")


def _read_env(path) -> dict:
    out: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def main() -> int:
    env_path = ROOT / ".env"
    existing = _read_env(env_path)
    added = []
    for key in ENV_SECRETS:
        if key not in existing:
            existing[key] = _secrets.token_urlsafe(32)
            added.append(key)

    lines = [f"{k}={v}" for k, v in existing.items()]
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    env_path.chmod(0o600)
    log(STEP, f".env written (0600); added {added or 'nothing (all present)'}")

    keys_dir = ROOT / ".airgap" / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv = keys_dir / "manifest_ed25519"
    pub = keys_dir / "manifest_ed25519.pub"
    if not priv.exists():
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        sk = ed25519.Ed25519PrivateKey.generate()
        priv.write_bytes(
            sk.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        priv.chmod(0o600)
        pub.write_bytes(
            sk.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        pub.chmod(0o644)
        log(STEP, f"generated Ed25519 keypair at {keys_dir} (private 0600, public 0644)")
    else:
        log(STEP, "Ed25519 keypair already present — left untouched")

    # sanity: private key must be 0600
    mode = stat.S_IMODE(priv.stat().st_mode)
    assert mode == 0o600, f"private key mode {oct(mode)} != 0600"
    log(STEP, "done (no secret value printed — by design)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
