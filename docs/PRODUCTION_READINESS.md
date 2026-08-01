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
| CI configured | GREEN | `.github/workflows/ci.yml` (Actions SHA-pinned, node24) |
| Dependency CVE scan | GREEN | `make audit-deps` (`pip-audit`) — no known vulnerabilities; CI gate |
| SAST | GREEN | `make sast` (bandit) — no findings; CI gate. Dormant CodeQL workflow auto-activates when the repo is made public |
| SBOM | GREEN | `make sbom` → `sbom.cdx.json` (CycloneDX 1.6, 84 runtime components) |
| Disclosure policy | GREEN | `SECURITY.md` (scope + threat model); Dependabot watches deps + pinned Actions |
| App image builds | GREEN | `docker build` → 639 MB, `import sagp` OK (Linux shape; caveats in `Dockerfile`) |
| Online negative control | GREEN | `verify-online-<gen>.json` blocked every probe |

The FPR gap is the one measured miss. It is **not** a hard-gate failure (recall and PII
are the hard gates; precision/FPR are regression-gated targets). The **entire** classifier
field was swept — 8 candidates, 29M–279M, **including Llama Prompt Guard 2** via an ungated
ONNX re-host ([docs/metrics/candidates/](metrics/candidates/)) — and **every one that
lowers FPR does so by dropping attack recall**, collapsing family F (indirect injection) to
0.25–0.75. The baseline is the only model that holds F at 1.0. So the gap is a genuine
recall/FPR **frontier**, not a missing model: closing it needs an ensemble or a fine-tune
(**H5**), not a swap. This also settles the earlier "get an HF token for PG2" ask — PG2
was measured and it fails the same gate, so the Meta licence + PII form is not worth it.

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

### Last full gate run — 2026-08-02 (this provisioned dev host)

Every runnable gate executed; results captured, not asserted:

| gate | result |
|---|---|
| `make lint` / `typecheck` | green (126 files formatted; mypy strict, 72 files) |
| `make test-all` | **277 passed** in 2:11 (real ONNX + spaCy + Ollama) |
| `make eval` | recall 1.0, precision 0.854, FPR 0.24, PII EMAIL/CARD/AADHAAR/PERSON all 1.0 (baseline reproduced) |
| `make smoke` | **14/14 PASS** (guard armed · manifest verified · PII masked pre-LLM · injection→400 · audit chain intact) |
| `make audit-verify` | chain OK, 146 records |
| `make bench` | app-process RSS 795 MB, build 2.7 s, benign chat 4.2 s (Ollama-bound), injection→400 960 ms — single-host/idle, not load-tested |
| `make verify` | 9/9 assertions PASS, verdict **INVALID** — correct: phase=PROVISION + non-loopback dev listeners (only H1 changes this) |
| `make production-preflight` | **NOT READY** — hard gates green, 1 tracked FPR GAP, RUN+HUMAN gates open |

Every automated gate is green; the only non-green verdicts (`verify` INVALID, `preflight`
NOT READY) are the honest consequence of an unsealed dev host, and only H1–H7 change them.

## 3. Human / external — the real remaining distance

None of these can be automated from inside the repo. Each names its owner-action.

| # | gate | action | why it can't be automated |
|---|---|---|---|
| **H1** | Physical seal + disconnect | `make seal` → physically disconnect → `make verify` / `make proof` (green `PASS`) | requires physically removing the network; only that turns `INVALID` into `PASS` |
| **H2** | Host egress lockdown | `make seal-pf` (sudo, host-wide pf) | root, host-wide; covers native code (grpcio C core, ORT, ctypes) the Python guard can't |
| **H3** | Key custody | replace the self-signed Ed25519 key with an HSM/KMS; export the ledger head off-box | self-signed is tamper-*evident*, not provenance; real custody is hardware/external |
| **H4** | Third-party audit | commission an independent security review | a self-audit is a starting point, never a pass |
| **H5** | Close the FPR ceiling | build an **ensemble** (baseline for recall + a low-FPR corroborator) or **fine-tune** on the deployed corpus | **not a swap** — the whole model field was swept, incl. Prompt Guard 2 (see below); no off-the-shelf model closes it without regressing recall |
| **H6** | Real target + soak | choose a deployment host and run a sustained load/soak (not a burst) | needs a real environment and time; current numbers are single-host bursts |
| **H7** | Host hardening | FileVault on; `ulimit -c 0` | operator host configuration; the request-scoped vault survives a core dump otherwise |

## 4. What would let me close more

- **H5 is now answered, not blocked.** The full field (incl. Prompt Guard 2, via an ungated re-host) was evaluated; none closes the FPR gap without regressing recall. The remaining work is an ensemble or a fine-tune — real engineering I can *start* against the current corpus, but which only pays off measured against a real deployment corpus (**H6**). No HF token needed.
- **H6** (partial) — name a deployment target (host/OS/expected load) and I'll write the deployment-specific config, a soak harness, and the tuned budget for it.

The rest — the physical seal, host-wide pf, an HSM, an external audit — are yours or a third party's to perform. The code is ready to be taken through them; it cannot take itself.
