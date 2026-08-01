# ADR-0002: Qdrant is the only vector store; embedded is the default runtime backend, `PROFILE=demo` (Docker) is the demonstration and proof path

Records why Chroma was deleted, why embedded Qdrant is the default runtime backend on RAM grounds while `PROFILE=demo` (Docker) is the demonstration and proof path the project targets, and — now that `make spike-docker` has run — the empirical resolution of OQ-4/OQ-5 about Docker Desktop network isolation.

- **Status:** **Accepted** — `make spike-docker` run 2026-08-01; OQ-4/OQ-5 RESOLVED (see below)
- **Date:** 2026-07-27 (decision); 2026-08-01 (spike run, OQ-4/OQ-5 resolved)
- **Deciders:** Project architect
- **Supersedes:** —

> **Spike run 2026-08-01 (`make spike-docker`, Docker Desktop 29.5.3, macOS; `evidence/spike-docker.json`).** The embedded backend is implemented and works (M8/M9, the default). The spike settled both open questions **negatively for the Docker path**:
> - **OQ-4 → PUBLISH-NO-ROUTE.** With `internal: true`, a published `127.0.0.1` port is *accepted* and the container *runs*, but the host cannot reach it (`http_code=000`). So `internal: true` and a host-app-reachable Qdrant are **mutually exclusive** on Docker Desktop.
> - **OQ-5 → egress not stopped by Docker options.** On the internal network, raw TCP egress to `1.1.1.1` is blocked **but DNS still resolves** `example.com` via the embedded resolver (a real, if limited, channel). On a *reachable* (non-internal) network with `enable_ip_masquerade=false`, egress is **fully open** (`1.1.1.1` reached, DNS resolves) — the userland VM proxy bridges out regardless of the option.
>
> **Conclusion:** on Docker Desktop you cannot get *both* "app-reachable Qdrant" *and* "egress-blocked container" from compose network options alone. Container-level egress control for the Docker path must come from the host `pf` anchor (`make seal-pf`) + loopback binding — **not** from `internal:` (breaks reachability) or `enable_ip_masquerade=false` (does not block egress). DNS resolution always leaks via the embedded resolver. The demo `docker-compose.yml` therefore uses a **non-internal** bridge (so the app can reach Qdrant) and its docstring says plainly that Docker options do not isolate it. Say "not isolated by Docker options; egress-controlled by pf" — never "isolated".

## Context

Two subsystem specs disagreed: one shipped Chroma, one shipped Qdrant, and a third shipped a compose file that publishes `127.0.0.1:6333` on a network declared `internal: true` while flagging that combination as untested. The forces:

- **The demonstration needs a boundary to point at.** What the project sets out to show is that specific controls refuse specific probes at a network boundary. A container on a Docker network whose `Internal` flag is `true` is an artifact an auditor can inspect (`docker network inspect`); an in-process embedded library is not. `PROFILE=proof` attaches an `alpine:3` prober to the same network and runs egress probes from inside it.
- **The 8 GB ceiling is hard.** Docker Desktop's Linux VM (capped at 2 GB) plus the Qdrant container at `mem_limit 512m` puts the system at **~7.60 GB of 8 GB in the `PROFILE=demo` (Docker) profile** — no margin. The embedded profile projects **6.75 GB**, leaving 1.25 GB. Both are PROJECTIONS from BLUEPRINT §7, unmeasured; each figure names the profile it assumes.
- **Feature requirements.** Payload filters on `guard.verdict` (to exclude `quarantined` chunks at query time) and a separate never-retrieved `<collection>__quarantine` sibling collection. Qdrant provides both directly.
- **Docker Desktop networking was unmeasured at design time** (the daemon was stopped). The `make spike-docker` run on 2026-08-01 measured it — results in the box above and §"The Phase-0 spike" below.

## Decision

**Qdrant is the only vector store. Chroma is deleted from the design.** The client is `qdrant-client==1.18.0`, called through `query_points()` — `search()` was **removed** in 1.16.0, not merely deprecated. Results are at `.points`; the filter kwarg is `query_filter=`. Vectors are 384-d, `Distance.COSINE`.

**`SAGP_QDRANT_MODE=embedded` is the default runtime backend**, on RAM grounds: the embedded profile projects 6.75 GB against an 8 GB ceiling, the demo/Docker profile projects 7.60 GB (both PROJECTIONS, BLUEPRINT §7).

**`PROFILE=demo` (Docker, `qdrant/qdrant:v1.18.3-unprivileged`, pinned by digest and `docker save`d during provisioning) is the demonstration and proof path the project targets** — the network-isolation boundary this project exists to show, and the path the proof harness targets — because a real network boundary is what can be inspected and probed. It is one env var away and costs ~0.85 GB. Both modes sit behind one class, `rag/qdrant_store.py`, with a third `":memory:"` mode for tests.

This ADR does not supersede [BLUEPRINT §0 row 8](../BLUEPRINT.md); the RAM argument recorded there is the reason embedded is the default runtime backend.

### The two OPEN QUESTIONS — now RESOLVED

**OQ-4 — can `internal: true` coexist with a published `127.0.0.1:6333` port on Docker Desktop for Mac 29.5.3? → NO (RESOLVED 2026-08-01).** FastAPI runs on the macOS host, not in a container, so the only host↔Qdrant path is a published loopback port. The spike created an `--internal` network, ran busybox `httpd` with `-p 127.0.0.1:16333:80`, confirmed the container was `Running=true`, and got `http_code=000` from the host — the publish is accepted but does **not** route. **`internal: true` and a host-reachable Qdrant are mutually exclusive**, so the compose file drops `internal: true`.

**OQ-5 — does `com.docker.network.bridge.enable_ip_masquerade: "false"` actually block egress on Docker Desktop? → NO, not on the path that matters (RESOLVED 2026-08-01).** As suspected, Docker Desktop containers egress through a **userland VM proxy**, not a host MASQUERADE rule. The spike measured: on the *internal* network, TCP to `1.1.1.1` is blocked but DNS still resolves; on a *reachable* (non-internal) network with `enable_ip_masquerade=false`, egress is **fully open** (TCP reached, DNS resolves). So the option has no effect on the reachable config, and DNS always leaks via the embedded resolver. See [LIMITATIONS](../LIMITATIONS.md) item 19.

### The Phase-0 spike — `make spike-docker` (RUN 2026-08-01)

`scripts/spike_docker.sh` created the networks, ran the probes, wrote `evidence/spike-docker.json`, and cleaned up (trap). The measured result:

```
Docker server 29.5.3   network .Internal=true   masquerade-opt-accepted=yes
OQ-4: PUBLISH-NO-ROUTE   (publish_accepted=yes server_running=true host_reachable=no http=000)
OQ-5: internal net blocks TCP egress but DNS RESOLVED (partial leak via embedded resolver)
Test B (non-internal + masquerade=false): host_reachable=yes http=404,
        tcp_egress=REACHED, dns=RESOLVED  → egress fully open; needs pf
```

The negative result is recorded here verbatim, as promised: a compose file that publishes a port on a network the docs call isolated would be exactly the overclaim this project exists to avoid — so the docs now say the Docker path is **not isolated by Docker options** and its egress is controlled by `make seal-pf`, not by `internal:`/`masquerade`.

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
- **The Docker path is NOT network-isolated by compose options (RESOLVED by the spike).** `internal: true` would isolate it but breaks host→Qdrant reachability (OQ-4); a reachable network leaks egress fully regardless of `enable_ip_masquerade` (OQ-5); DNS always resolves via the embedded resolver. Egress control for the Docker path therefore depends on `make seal-pf` (host pf) + loopback binding, not on Docker networking. This is a real reduction from the original hope of an inspectable, self-isolating `internal` network — say "not isolated by Docker options", never "isolated".
- Docker's own traffic leaves via a root-owned VM interface and is covered by neither Python guard layer nor by pf. `docker exec` egress tests measure Docker Desktop's Linux VM, not macOS — a different host.

### Neutral
- Provisioning pins the image by digest and `docker save`s it to `models/docker/`, so `PROFILE=demo` is offline-startable like everything else. Tests use `":memory:"`, so neither Docker nor an on-disk path is a test dependency.

## Verification

```bash
make spike-docker            # RUN 2026-08-01 — resolved OQ-4/OQ-5; result in evidence/spike-docker.json + above
make up                      # PROFILE=demo: docker load + compose up qdrant (non-internal bridge)
```

Gates: `make smoke` check `[ 7/14]` is implemented and passes — it requires the store to initialise in the configured mode (embedded, on this host). `make spike-docker` has run and recorded its result above.

Because the spike showed the Docker path is **not** self-isolating (OQ-4/OQ-5), a `PROFILE=proof` verdict about container egress cannot rest on `.Internal == true` — that config is unreachable by the host app. Any `PROFILE=proof` egress claim must instead be carried by the host `pf` anchor (`make seal-pf`, now built — `deploy/pf/com.sagp`, syntax-validated; operator-loaded, and note it does not cover Docker's own root-owned VM interface) covering the container's traffic, and any high-severity gap left `OPEN` must yield `PASS_WITH_OPEN_HIGH_SEVERITY_GAPS`, never `PASS`. The DNS-resolution leak via the embedded resolver is a residual even then.

---

[ADR index](../ARCHITECTURE.md) · [Blueprint](../BLUEPRINT.md) · [Plan](../PLAN.md) · [Air-gap runbook](../AIRGAP_RUNBOOK.md) · [Limitations](../LIMITATIONS.md)
