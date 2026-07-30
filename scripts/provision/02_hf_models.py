"""02 — download the HuggingFace models pinned in artifacts.lock.

Uses snapshot_download at the exact commit SHA with allow_patterns, into
models/hf/<name>. Verifies the byte sizes recorded in artifacts.lock so a
truncated or substituted download fails here, online, rather than at boot.
"""

from __future__ import annotations

from _common import ROOT, die, human, load_artifacts, log

STEP = "02_hf_models"


def main() -> int:
    from huggingface_hub import snapshot_download

    arts = load_artifacts()
    for m in arts.get("hf_model", []):
        local = ROOT / m["local_dir"]
        local.mkdir(parents=True, exist_ok=True)
        log(STEP, f"{m['id']} @ {m['revision'][:12]} -> {m['local_dir']}")
        snapshot_download(
            repo_id=m["id"],
            revision=m["revision"],
            local_dir=str(local),
            allow_patterns=m.get("allow_patterns"),
        )
        for rel, expected in m.get("bytes", {}).items():
            got = (local / rel).stat().st_size
            if got != expected:
                die(STEP, f"{m['id']}/{rel}: size {got} != expected {expected}")
            log(STEP, f"  verified {rel} = {human(got)}")
    log(STEP, "done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
