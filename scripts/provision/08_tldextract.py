"""08 — warm the tldextract Public Suffix List snapshot into models/tldextract.

Presidio's EmailRecognizer calls tldextract, which fetches the PSL over HTTPS on
first use — an EgressViolation on a sealed box. We warm the cache HERE (online),
using the SAME sealed constructor the runtime uses (suffix_list_urls=()), so the
cache key matches and the runtime reads it. The bundled snapshot is what actually
guarantees no fetch; this step is for PSL freshness + manifest determinism.
"""

from __future__ import annotations

from _common import ROOT, log

STEP = "08_tldextract"


def main() -> int:
    import tldextract

    cache_dir = ROOT / "models" / "tldextract"
    cache_dir.mkdir(parents=True, exist_ok=True)
    extract = tldextract.TLDExtract(
        suffix_list_urls=(),  # no HTTP fetch; bundled snapshot only
        cache_dir=str(cache_dir),
        fallback_to_snapshot=True,
    )
    # Exercise it so the snapshot is materialised in the cache dir.
    res = extract("user@example.co.uk")
    assert res.fqdn == "example.co.uk", res
    log(STEP, f"warmed PSL snapshot at {cache_dir} (fqdn check OK)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
