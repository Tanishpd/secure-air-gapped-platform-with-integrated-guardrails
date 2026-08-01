#!/usr/bin/env bash
# make unseal-pf — reverse `make seal-pf`. Restores the /etc/pf.conf backup (so the
# com.sagp anchor is no longer referenced), reloads the main ruleset, and flushes
# the anchor's rules. It does NOT run `pfctl -d`: pf may have been on for other
# reasons before you sealed, so disabling it is left as an explicit operator choice.
set -euo pipefail
PFCONF="/etc/pf.conf"
BACKUP="/etc/pf.conf.sagp-backup"

if [ -f "$BACKUP" ]; then
  sudo cp "$BACKUP" "$PFCONF"
  echo "unseal-pf: restored $PFCONF from $BACKUP"
else
  # No backup — strip our appended block in place instead.
  sudo sed -i '' '/# --- sagp air-gap anchor (added by make seal-pf) ---/,+2d' "$PFCONF" || true
  echo "unseal-pf: no backup found; removed the com.sagp anchor lines from $PFCONF"
fi

sudo pfctl -f "$PFCONF"                 # reload without the com.sagp anchor
sudo pfctl -a com.sagp -F rules || true # flush any rules left in the anchor
echo "unseal-pf: com.sagp anchor removed and flushed; main ruleset reloaded."
echo "          pf is left in its current enabled/disabled state — run 'sudo pfctl -d' to disable it if you enabled it only for sagp."
