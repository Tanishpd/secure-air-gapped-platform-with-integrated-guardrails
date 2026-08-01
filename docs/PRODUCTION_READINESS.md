# Production readiness — the honest go/no-go

> **This system is NOT production-ready, and this document is the gated path to it —
> not a claim that it has been walked.** `sagp` is a reference *template*: the code is
> built, tested, and instrumented to a production grade, but "production-ready" is a
> property of a *deployment* — a specific host, sealed and disconnected, with real key
> custody and an external sign-off — none of which a repository can assert about itself.
> A compliance-themed system that calls itself ready before those is worse than none;
> that refusal is the whole point (see [LIMITATIONS.md](LIMITATIONS.md)).

Run the mechanical gate any time:

```bash
make production-preflight     # exits nonzero until every gate is closed — by design
```

It checks what can be checked here and prints the rest as explicit RUN / HUMAN gates.
A **green preflight is necessary, never sufficient**: the air-gap `PASS` still requires
the physical seal + disconnect.

## Status vocabulary

| | meaning |
|---|---|
| **GREEN** | automated check passed, here, now |
| **RED** | automated check failed — a real, closeable defect; fix before anything else |
| **GAP** | a tracked, documented known-gap whose closure needs an external input, not a fix |
| **RUN** | an existing gate must be executed (command given); some cannot PASS until sealed |
| **HUMAN** | requires an operator action, a credential, or hardware — cannot be automated |

## 1. Automated — green now

| gate | status | criterion |
|---|---|---|
| Injection recall floor | GREEN | headline recall 1.0 ≥ 0.90 (hard gate) |
| Injection precision floor | GREEN | 0.854 ≥ 0.85 |
| PII recall floors | GREEN | EMAIL/CARD/AADHAAR/PERSON all ≥ floor (hard gate) |
| No OPEN high-severity gaps | GREEN | 0 open (invariant 13) |
| Benign FPR ceiling | **GAP** | 0.24 > 0.10 — tracked, medium; only closer is a better classifier (**H5**) |
| Signed manifest present | GREEN | `models/MANIFEST.json` (full recompute is R‑manifest) |
| Guardrail config valid | GREEN | `guardrails.yaml` + `entities.yaml` parse & validate (invariant 12) |
| Egress guard importable | GREEN | `sagp.netguard.egress` |
| CI configured | GREEN | `.github/workflows/ci.yml` |
| Online negative control | GREEN | `verify-online-<gen>.json` blocked every probe |

The FPR gap is the one measured miss. It is **not** a hard-gate failure (recall and PII
are the hard gates; precision/FPR are regression-gated targets). The ungated classifier
landscape was swept — [docs/metrics/candidates/](metrics/candidates/) — and every ungated
model that lowers FPR does so by dropping attack recall, so the gap is genuinely a
"needs a stronger model" (**H5**), not a tuning task.

## 2. Run — existing gates to execute

| gate | command | criterion | note |
|---|---|---|---|
| Code + types + fast tests | `make lint typecheck test-ci` | green | also runs in CI on every push |
| Full suite | `make test-all` / `make test-e2e` | green | needs models + Ollama (provisioned host) |
| Metrics | `make eval` | floors hold, no >2pp regression | regenerates `docs/metrics/latest.json` |
| Smoke | `make smoke` | 14/14 | end-to-end, guard armed |
| Air-gap assertions | `make verify` | PASS | **INVALID until sealed + offline** — this is correct on a dev host |
| Proof | `make proof` | signed `PASS` | verify + evidence; the artifact the project exists to produce |

`make verify` returning `INVALID` here is not a failure — it fails identically whether the
network is merely absent or genuinely blocked, which is why a `PASS` is only meaningful
after the physical disconnect (H1).

## 3. Human / external — the real remaining distance

None of these can be automated from inside the repo. Each names its owner-action.

| # | gate | action | why it can't be automated |
|---|---|---|---|
| **H1** | Physical seal + disconnect | `make seal` → physically disconnect → `make verify` / `make proof` (green `PASS`) | requires physically removing the network; only that turns `INVALID` into `PASS` |
| **H2** | Host egress lockdown | `make seal-pf` (sudo, host-wide pf) | root, host-wide; covers native code (grpcio C core, ORT, ctypes) the Python guard can't |
| **H3** | Key custody | replace the self-signed Ed25519 key with an HSM/KMS; export the ledger head off-box | self-signed is tamper-*evident*, not provenance; real custody is hardware/external |
| **H4** | Third-party audit | commission an independent security review | a self-audit is a starting point, never a pass |
| **H5** | Close the FPR ceiling | provide an HF token with the Meta licence accepted, then `make eval-candidate CANDIDATE=meta-llama/Llama-Prompt-Guard-2-86M NAME=prompt-guard-2` | PG2 is `gated=manual`; it cannot be fetched without your credentials (confirmed `GatedRepoError: 401`) |
| **H6** | Real target + soak | choose a deployment host and run a sustained load/soak (not a burst) | needs a real environment and time; current numbers are single-host bursts |
| **H7** | Host hardening | FileVault on; `ulimit -c 0` | operator host configuration; the request-scoped vault survives a core dump otherwise |

## 4. What would let me close more

Two of the above are one input away from me acting:

- **H5** — give me an HF token whose account has accepted the Meta Prompt Guard 2 licence, and I'll run PG2 through the bake-off gate immediately and report whether it closes the FPR ceiling without regressing recall.
- **H6** (partial) — name a deployment target (host/OS/expected load) and I'll write the deployment-specific config, a soak harness, and the tuned budget for it.

The rest — the physical seal, host-wide pf, an HSM, an external audit — are yours or a third party's to perform. The code is ready to be taken through them; it cannot take itself.
