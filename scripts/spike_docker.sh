#!/usr/bin/env bash
# make spike-docker — the ~10-minute empirical resolution of OQ-4 and OQ-5
# (ADR-0002). Run ONLINE, in BOOTSTRAP/PROVISION, with Docker running. It answers
# two questions the design cannot answer by reasoning, both specific to Docker
# Desktop's Linux-VM + userland-proxy networking:
#
#   OQ-4  Can `internal: true` coexist with a published 127.0.0.1 port? I.e. if the
#         demo network is internal AND Qdrant's port is published to loopback, can
#         the HOST (the sagp app) still reach it — or does publishing silently not
#         route on an internal network?
#   OQ-5  Does an internal network (+ enable_ip_masquerade=false) actually BLOCK a
#         container's egress on Docker Desktop, where containers egress through a
#         userland VM proxy rather than a host MASQUERADE rule?
#
# Writes evidence/spike-docker.json + a human summary. Never leaves containers or
# networks behind (trap cleanup). Uses busybox (tiny) as both the server and the
# egress prober. NOT run automatically anywhere — an operator runs it once.
set -uo pipefail  # deliberately NOT -e: a "blocked" probe is a NON-zero exit we must observe, not abort on
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NET=sagp_spike_internal
NETB=sagp_spike_reachable
SRV=sagp_spike_srv
SRVB=sagp_spike_srv_b
IMG=busybox:1.37
PORT=16333
PORTB=16334

cleanup() {
  docker rm -f "$SRV" "$SRVB" >/dev/null 2>&1 || true
  docker network rm "$NET" "$NETB" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup  # pre-clean any stale run

if ! docker info >/dev/null 2>&1; then
  echo "spike-docker: Docker daemon not reachable — run 'open -a Docker' first." >&2
  exit 1
fi

echo "spike-docker: pulling $IMG ..."
docker pull "$IMG" >/dev/null 2>&1 || { echo "cannot pull $IMG (need internet)" >&2; exit 1; }

echo "spike-docker: creating internal network ($NET, enable_ip_masquerade=false) ..."
net_opt_accepted="yes"
if ! docker network create --internal \
      --opt com.docker.network.bridge.enable_ip_masquerade=false "$NET" >/dev/null 2>&1; then
  # Retry without the bridge opt (Docker Desktop may reject it) so we can still test --internal.
  net_opt_accepted="no"
  docker network create --internal "$NET" >/dev/null
fi
net_internal=$(docker network inspect "$NET" --format '{{.Internal}}' 2>/dev/null || echo "unknown")

# --- OQ-4: publish a loopback port on the internal network ---
echo "spike-docker: OQ-4 — publishing 127.0.0.1:$PORT on the internal network ..."
oq4_publish_accepted="no"; oq4_host_reachable="no"; oq4_http=""
if docker run -d --name "$SRV" --network "$NET" -p "127.0.0.1:$PORT:80" "$IMG" \
      httpd -f -p 80 -h /etc >/dev/null 2>&1; then
  oq4_publish_accepted="yes"
  sleep 2
  oq4_running=$(docker inspect -f '{{.State.Running}}' "$SRV" 2>/dev/null || echo "unknown")
  # curl -w prints the http_code even on a failed connection (000); no `|| echo` (it would
  # double-print and defeat the 000 check). A real response (even 404) => reachable.
  oq4_http=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/" 2>/dev/null)
  oq4_http=${oq4_http:-000}
  [ "$oq4_http" != "000" ] && oq4_host_reachable="yes"
fi

# --- OQ-5: can a container on the internal network egress? ---
echo "spike-docker: OQ-5 — probing egress from inside the internal network ..."
oq5_tcp="blocked"; oq5_dns="blocked"
# Direct external IP, no DNS (the cleanest egress signal): wget http://1.1.1.1/
if docker run --rm --network "$NET" "$IMG" \
      sh -c 'wget -T 5 -q -O /dev/null http://1.1.1.1/ 2>/dev/null'; then
  oq5_tcp="REACHED"
fi
# DNS resolution of a public name via the embedded resolver.
if docker run --rm --network "$NET" "$IMG" \
      sh -c 'nslookup -type=a example.com 2>/dev/null | grep -q "Address"'; then
  oq5_dns="RESOLVED"
fi

# --- Test B: the REACHABLE config (non-internal bridge + masquerade=false) ---
# OQ-4 showed internal+published does not route, so the host app needs a NON-internal
# network. Does masquerade=false on such a network still block container egress, or
# does Docker Desktop's userland proxy provide egress anyway?
echo "spike-docker: Test B — non-internal bridge + masquerade=false (reachable config) ..."
docker network create --opt com.docker.network.bridge.enable_ip_masquerade=false "$NETB" >/dev/null 2>&1 \
  || docker network create "$NETB" >/dev/null
b_host_reachable="no"; b_http=""
if docker run -d --name "$SRVB" --network "$NETB" -p "127.0.0.1:$PORTB:80" "$IMG" \
      httpd -f -p 80 -h /etc >/dev/null 2>&1; then
  sleep 2
  b_http=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORTB/" 2>/dev/null)
  b_http=${b_http:-000}
  [ "$b_http" != "000" ] && b_host_reachable="yes"
fi
b_tcp="blocked"; b_dns="blocked"
docker run --rm --network "$NETB" "$IMG" sh -c 'wget -T 5 -q -O /dev/null http://1.1.1.1/ 2>/dev/null' && b_tcp="REACHED"
docker run --rm --network "$NETB" "$IMG" sh -c 'nslookup -type=a example.com 2>/dev/null | grep -q "Address"' && b_dns="RESOLVED"
if [ "$b_host_reachable" = "yes" ] && [ "$b_tcp" = "blocked" ]; then
  b_verdict="REACHABLE + TCP-EGRESS-BLOCKED (masquerade=false works; DNS=$b_dns still resolves)"
elif [ "$b_host_reachable" = "yes" ]; then
  b_verdict="REACHABLE but TCP-EGRESS-LEAKS ($b_tcp) — masquerade=false does not stop egress; needs pf"
else
  b_verdict="host cannot reach it (http=$b_http) — unexpected for a non-internal network"
fi

# --- verdicts ---
if [ "$oq4_publish_accepted" = "yes" ] && [ "$oq4_host_reachable" = "yes" ]; then
  oq4_verdict="COEXIST — published loopback port routes on an internal network (host can reach Qdrant)"
elif [ "$oq4_publish_accepted" = "yes" ]; then
  oq4_verdict="PUBLISH-NO-ROUTE — port accepted but host cannot reach it; the demo app could not reach Qdrant"
else
  oq4_verdict="PUBLISH-REFUSED — Docker refused to publish a port on the internal network"
fi
if [ "$oq5_tcp" = "blocked" ] && [ "$oq5_dns" = "blocked" ]; then
  oq5_verdict="EGRESS-BLOCKED — internal network blocks container egress (VM proxy does NOT bypass)"
else
  oq5_verdict="EGRESS-LEAKS — container reached the internet despite internal:true (userland proxy bypass)"
fi

mkdir -p "$ROOT/evidence"
cat > "$ROOT/evidence/spike-docker.json" <<JSON
{
  "docker_server_version": "$(docker info --format '{{.ServerVersion}}' 2>/dev/null)",
  "network_internal": "$net_internal",
  "enable_ip_masquerade_opt_accepted": "$net_opt_accepted",
  "oq4": {
    "publish_accepted": "$oq4_publish_accepted",
    "server_running": "${oq4_running:-n/a}",
    "host_reachable": "$oq4_host_reachable",
    "http_code": "$oq4_http",
    "verdict": "$oq4_verdict"
  },
  "oq5": {
    "tcp_egress_1.1.1.1": "$oq5_tcp",
    "dns_example.com": "$oq5_dns",
    "verdict": "$oq5_verdict"
  },
  "test_b_reachable_config": {
    "network": "non-internal bridge, enable_ip_masquerade=false",
    "host_reachable": "$b_host_reachable",
    "http_code": "$b_http",
    "tcp_egress_1.1.1.1": "$b_tcp",
    "dns_example.com": "$b_dns",
    "verdict": "$b_verdict"
  }
}
JSON

echo "========================================================================"
echo "  make spike-docker — OQ-4 / OQ-5 empirical result"
echo "========================================================================"
echo "  Docker server: $(docker info --format '{{.ServerVersion}}' 2>/dev/null)   network .Internal=$net_internal   masquerade-opt-accepted=$net_opt_accepted"
echo "  OQ-4: $oq4_verdict"
echo "        (publish_accepted=$oq4_publish_accepted host_reachable=$oq4_host_reachable http=$oq4_http)"
echo "  OQ-5: $oq5_verdict"
echo "        (tcp_egress=$oq5_tcp dns=$oq5_dns)"
echo "  Test B (reachable config): $b_verdict"
echo "        (host_reachable=$b_host_reachable http=$b_http tcp_egress=$b_tcp dns=$b_dns)"
echo "  wrote evidence/spike-docker.json"
echo "========================================================================"
