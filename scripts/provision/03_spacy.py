"""03 — fetch the spaCy pipeline wheels and install the default into .venv.

Wheels are downloaded to models/spacy/ (so they are in the manifest and the
offline install can use them) and the default model is pip-installed into the
RUNTIME venv (.venv), because Presidio resolves it via ``spacy.util.is_package``.
"""

from __future__ import annotations

import subprocess
import urllib.request

from _common import ROOT, die, human, load_artifacts, log

STEP = "03_spacy"


def main() -> int:
    arts = load_artifacts()
    dest = ROOT / "models" / "spacy"
    dest.mkdir(parents=True, exist_ok=True)
    runtime_pip = ROOT / ".venv" / "bin" / "pip"

    for m in arts.get("spacy_model", []):
        whl = dest / m["url"].rsplit("/", 1)[-1]
        if not whl.exists():
            log(STEP, f"downloading {m['name']}-{m['version']}")
            urllib.request.urlretrieve(m["url"], whl)  # noqa: S310 (pinned GitHub release URL)
        got = whl.stat().st_size
        if got != m["bytes"]:
            die(STEP, f"{whl.name}: size {got} != expected {m['bytes']}")
        log(STEP, f"  verified {whl.name} = {human(got)}")
        if m.get("role") == "default":
            if not runtime_pip.exists():
                die(STEP, "runtime .venv missing — run `make install` first")
            log(STEP, f"installing {m['name']} into .venv")
            subprocess.run(  # noqa: S603
                [str(runtime_pip), "install", "--no-index", "--no-deps", str(whl)],
                check=True,
            )
    log(STEP, "done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
