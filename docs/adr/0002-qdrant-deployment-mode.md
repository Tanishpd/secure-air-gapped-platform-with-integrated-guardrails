# ADR-0002: Qdrant is the only vector store; embedded is the default runtime backend, `PROFILE=demo` (Docker) is the demonstration and proof path

Records why Chroma was deleted, why embedded Qdrant is the default runtime backend on RAM grounds while `PROFILE=demo` (Docker) is the demonstration and proof path the project targets, and the two genuinely open questions about Docker Desktop network isolation that a Phase-0 spike must resolve.

- **Status:** Proposed — blocked on the Phase-0 spike (OQ-4/OQ-5)
- **Date:** 2026-07-27
- **Deciders:** Project architect
- **Supersedes:** —

> **Until `make spike-docker` runs, the isolation properties of the Docker path are untested and every document must say "untested", not "isolated".**

## Context

Two subsystem specs disagreed: one shipped Chroma, one shipped Qdrant, and a third shipped a compose file that publishes `127.0.0.1:6333` on a network declared `internal: true` while flagging that combination as untested. The forces:

- **The demonstration needs a boundary to point at.** What the project sets out to show is that specific controls refuse specific probes at a network boundary. A container on a Docker network whose `Internal` flag is `true` is an artifact an auditor can inspect (`docker network inspect`); an in-process embedded library is not. `PROFILE=proof` attaches an `alpine:3` prober to the same network and runs egress probes from inside it.
- **The 8 GB ceiling is hard.** Docker Desktop's Linux VM (capped at 2 GB) plus the Qdrant container at `mem_limit 512m` puts the system at **~7.60 GB of 8 GB in the `PROFILE=demo` (Docker) profile** — no margin. The embedded profile projects **6.75 GB**, leaving 1.25 GB. Both are PROJECTIONS from BLUEPRINT §7, unmeasured; each figure names the profile it assumes.
- **Feature requirements.** Payload filters on `guard.verdict` (to exclude `quarantined` chunks at query time) and a separate `docs_quarantine` collection. Qdrant provides both directly.
- **The Docker daemon is currently stopped** (Docker 29.5.3 installed, not running), so nothing about its network behaviour has been measured on this host.

## Decision

**Qdrant is the only vector store. Chroma is deleted from the design.** The client is `qdrant-client==1.18.0`, called through `query_points()` — `search()` was **removed** in 1.16.0, not merely deprecated. Results are at `.points`; the filter kwarg is `query_filter=`. Vectors are 384-d, `Distance.COSINE`.

**`SAGP_QDRANT_MODE=embedded` is the default runtime backend**, on RAM grounds: the embedded profile projects 6.75 GB against an 8 GB ceiling, the demo/Docker profile projects 7.60 GB (both PROJECTIONS, BLUEPRINT §7).

**`PROFILE=demo` (Docker, `qdrant/qdrant:v1.18.3-unprivileged`, pinned by digest and `docker save`d during provisioning) is the demonstration and proof path the project targets** — the network-isolation boundary this project exists to show, and the path the proof harness targets — because a real network boundary is what can be inspected and probed. It is one env var away and costs ~0.85 GB. Both modes sit behind one class, `rag/qdrant_store.py`, with a third `":memory:"` mode for tests.

This ADR does not supersede [BLUEPRINT §0 row 8](../BLUEPRINT.md); the RAM argument recorded there is the reason embedded is the default runtime backend.

### The two OPEN QUESTIONS this ADR must record

**OQ-4 — can `internal: true` coexist with a published `127.0.0.1:6333` port on Docker Desktop for Mac 29.5.3?** FastAPI runs on the macOS host, not in a container, so the only host↔Qdrant path is a published loopback port. One source spec asserts publishing on an internal network is impossible; another ships a compose file that does exactly that. **Neither was tested — the daemon is not running.** If publishing is impossible, the compose file must either drop `internal: true` or move the API into the network.

**OQ-5 — does `com.docker.network.bridge.enable_ip_masquerade: "false"` actually block egress on Docker Desktop?** It is a real Linux bridge-driver option key, but Docker Desktop containers egress through a **userland VM proxy**, not a host MASQUERADE rule, so the option may have no effect on the path that matters. This must be **measured** by a prober attached to `sagp_vec_noegress` — the network Qdrant actually runs on — and never asserted from a documentation page. See [LIMITATIONS](../LIMITATIONS.md) item 19.

### The Phase-0 spike — `make spike-docker`

This ADR stays **Proposed** until this command has run and its result is recorded below.

```bash
make spike-docker            # the command that unblocks this ADR; runs the sequence below

open -a Docker
docker network create --internal sagp_spike_internal    # OQ-4: does a published port survive?
docker run -d --name sagp_spike --network sagp_spike_internal -p 127.0.0.1:9999:80 nginx
curl -sv --max-time 3 http://127.0.0.1:9999/     # reachable? -> OQ-4 answered

# OQ-5: does disabling masquerade stop egress on Docker Desktop?
docker network create -o com.docker.network.bridge.enable_ip_masquerade=false sagp_spike_nomasq
docker run --rm --network sagp_spike_nomasq alpine:3 \
  sh -c 'wget -q -T3 -O- https://1.1.1.1 >/dev/null && echo EGRESS_WORKED || echo EGRESS_BLOCKED'

# Also probe `com.docker.network.bridge.gateway_mode_ipv4=isolated` before adopting it — enum unconfirmed.
docker rm -f sagp_spike; docker network rm sagp_spike_internal sagp_spike_nomasq
```

`make spike-docker` runs this in ~10 minutes during Phase 0; it has not been run, and no result is recorded here yet. **Whatever it finds will be recorded here verbatim, including a negative result.** A compose file that publishes a port on a network the docs call isolated is exactly the overclaim this project exists to avoid.

## Alternatives considered

| Option | Why it lost |
|---|---|
| **Chroma** | No payload-filter equivalent for the `guard.verdict` exclusion and the quarantine collection without hand-rolling it, and keeping two stores meant two score normalizations. `Hit.score` must always be cosine similarity; one store makes that checkable. Deleted outright. |
| **Both stores behind a Protocol** | A second backend doubles the surface that must be shown to work offline and doubles the score-normalization tests, for a store that would never be the demonstrated path. |
| **Embedded Qdrant as the demonstration path too** | Cheaper (6.75 GB embedded vs ~7.60 GB demo/Docker, both projected) and it is the default runtime backend for exactly that reason — but it gives the auditor nothing to inspect. There is no `docker network inspect` for an in-process library, and `PROFILE=proof`'s second prober has nowhere to attach, so it cannot carry the demonstration. |
| **Docker as the default runtime backend** | Costs ~0.85 GB and leaves the demo profile at ~7.60 GB of 8 GB with no margin (projected). Rejected as the *default*; retained as the demonstration and proof path. |
| **`prefer_grpc=False` to avoid the native gRPC core** | Does not help. `qdrant-client==1.18.0` hard-depends on `grpcio>=1.41.0`, `protobuf`, `httpx[http2]`, `portalocker` and `urllib3` regardless of transport. The `grpcio` C core is outside both Python egress-guard layers in either mode — a real, documented gap, not a mode-selection lever. |

## Consequences

### Positive
- One store, one score semantic, one set of tests. `query_points()` with `query_filter=` is the only query path.
- An inspectable boundary for the demonstration: `docker network inspect sagp_proof_internal → .Internal == true`, plus a prober on `sagp_vec_noegress` running the identical egress probes. Switching between the default embedded backend and the demo path is a single env var, not a code change.

### Negative
- **~7.60 GB of 8 GB in `PROFILE=demo` (PROJECTION — Docker profile, unmeasured).** It fits with no margin; other applications must be closed. The default embedded profile projects 6.75 GB, 1.25 GB of headroom.
- Isolation properties of the Docker path are **untested until the spike runs** — OQ-4 and OQ-5 are open. Until then every document must say "untested", not "isolated".
- Docker's own traffic leaves via a root-owned VM interface and is covered by neither Python guard layer nor by pf. `docker exec` egress tests measure Docker Desktop's Linux VM, not macOS — a different host.

### Neutral
- Provisioning pins the image by digest and `docker save`s it to `models/docker/`, so `PROFILE=demo` is offline-startable like everything else. Tests use `":memory:"`, so neither Docker nor an on-disk path is a test dependency.

## Verification

```bash
make spike-docker            # Phase 0 — must resolve OQ-4/OQ-5; the result is to be appended to this ADR. NOT YET RUN.
make up                      # PROFILE=demo: docker load + compose up qdrant
docker network inspect sagp_proof_internal --format '{{.Internal}}'      # expect: true

# The prober on the network Qdrant actually runs on — only this result may be cited.
docker run --rm --network sagp_vec_noegress alpine:3 \
  sh -c 'wget -q -T3 -O- https://1.1.1.1 >/dev/null && echo FAIL_EGRESS_WORKED || echo OK_BLOCKED'
```

Gates (specifications — none of these targets exists yet): `make smoke` check `[ 7/14]` is specified to require the store to initialise in the configured mode. `make verify` under `PROFILE=proof` is specified to add the `.Internal == true` assertion, the prober probes, the DNS test **paired with a positive control** (the prober *can* resolve a sibling service name), and a Docker daemon `>= 26.0.0` check for the CVE-2024-29018 regression. Any high-severity gap left `OPEN` must yield `PASS_WITH_OPEN_HIGH_SEVERITY_GAPS`, never `PASS`.

---

[ADR index](../ARCHITECTURE.md) · [Blueprint](../BLUEPRINT.md) · [Plan](../PLAN.md) · [Air-gap runbook](../AIRGAP_RUNBOOK.md) · [Limitations](../LIMITATIONS.md)
