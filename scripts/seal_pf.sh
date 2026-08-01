#!/usr/bin/env bash
# make seal-pf — OPTIONAL, sudo, host-wide. Loads the com.sagp pf anchor so the
# macOS packet filter blocks ALL non-loopback egress: the layer the in-process
# Python guard cannot be (native code, the sibling Ollama process, child
# processes) and the Docker demo path's egress control (ADR-0002).
#
# THIS BLOCKS THE ENTIRE MACHINE'S OUTBOUND TO NON-LOOPBACK once enforced — run it
# ONLY on a box you intend to air-gap. It is reversible with `make unseal-pf`
# (restores the /etc/pf.conf backup this script makes). It does NOT cover Docker's
# root-owned VM interface (documented gap, LIMITATIONS item 3).
#
# Safe by construction: it DRY-RUN PARSES the anchor first and refuses on any
# syntax error; it backs up /etc/pf.conf before touching it; and it is idempotent
# (re-running does not double-append). Requires confirmation unless FORCE=1.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANCHOR="$ROOT/deploy/pf/com.sagp"
PFCONF="/etc/pf.conf"
BACKUP="/etc/pf.conf.sagp-backup"

[ -f "$ANCHOR" ] || { echo "seal-pf: missing $ANCHOR" >&2; exit 1; }

echo "seal-pf: dry-run parsing the anchor (no load) ..."
sudo pfctl -n -f "$ANCHOR"    # refuses here on any syntax error
echo "seal-pf: anchor parses OK."

if [ "${FORCE:-0}" != "1" ]; then
  echo
  echo "  !! This will block ALL non-loopback egress from THIS ENTIRE MACHINE."
  echo "  !! Only proceed on a host you intend to air-gap. Reverse with 'make unseal-pf'."
  printf "  Type 'seal' to proceed: "
  read -r reply
  [ "$reply" = "seal" ] || { echo "seal-pf: aborted."; exit 1; }
fi

# 1. Back up /etc/pf.conf once (never overwrite an existing backup).
if [ ! -f "$BACKUP" ]; then
  sudo cp "$PFCONF" "$BACKUP"
  echo "seal-pf: backed up $PFCONF -> $BACKUP"
fi

# 2. Append the anchor references to /etc/pf.conf, idempotently. macOS pf requires
#    the `anchor`/`load anchor` lines in the main ruleset for the anchor to be
#    evaluated; appending at the end keeps Apple's com.apple anchors intact.
if ! grep -q 'anchor "com.sagp"' "$PFCONF"; then
  printf '\n# --- sagp air-gap anchor (added by make seal-pf) ---\nanchor "com.sagp"\nload anchor "com.sagp" from "%s"\n' \
    "$ANCHOR" | sudo tee -a "$PFCONF" >/dev/null
  echo "seal-pf: added com.sagp anchor references to $PFCONF"
fi

# 3. Reload the main ruleset (parses + loads the anchor) and enable pf.
sudo pfctl -f "$PFCONF"
sudo pfctl -E
echo "seal-pf: pf enabled; com.sagp anchor loaded."

echo
echo "Verify:   sudo pfctl -a com.sagp -s rules"
echo "          ping -c1 1.1.1.1                # MUST fail now"
echo "          curl -sS --max-time 3 http://127.0.0.1:11434/api/tags  # loopback still works"
echo "Reverse:  make unseal-pf"
