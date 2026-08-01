# Security policy

`sagp` is a **reference template**, self-signed and single-maintainer. There is no
paid support and no SLA — but security reports are genuinely welcome, and this file
tells you what counts as one so you don't spend effort on a documented design
boundary.

## Reporting a vulnerability

Use **GitHub's private vulnerability reporting**: the repository **Security** tab →
**Report a vulnerability**. That keeps the report private until a fix exists. Please
do **not** open a public issue for a suspected vulnerability.

Include: what you did, what happened, what you expected, and — ideally — a minimal
reproduction. Response is best-effort. Because the evidence signature is self-signed
and local-clock (tamper-evident, not provenance), an off-box report is the only
trustworthy channel.

## Supported versions

The `main` branch is the only supported line. There are no backports.

## In scope — these ARE vulnerabilities

A finding is in scope if it breaks a claim the system actually makes (the 13
invariants in `CLAUDE.md`, the guarantees in `docs/THREAT_MODEL.md`). For example:

- **Unscanned bytes reach the model.** Any path that gets text to `OllamaClient`
  without passing through `guardrails/pipeline.py` (invariant 3) — the flagship
  `test_final_bytes_were_scanned` is the contract.
- **The egress guard admits a non-loopback destination** without raising
  `EgressViolation`, in a phase where it is armed (invariant 2). Native-code and
  sibling-process bypasses are **out of scope** — see below.
- **Raw PII leaves the process**: in an audit record, a log line, an error body, or
  a response the caller shouldn't get it (invariant 1).
- **A detector oracle**: a rejection whose status/body/timing, or a returned score,
  count, or header, distinguishes one detector from another (invariant 8).
- **A guardrail fails open** — an error, timeout, or partial result that yields a
  200 instead of a 4xx/503 (invariant 6); or a way to disable a control via env/flag.
- **The vault persists or leaks** across requests (invariant 9), or a manifest/
  ledger tamper goes undetected.

## Out of scope — documented boundaries, NOT vulnerabilities

These are stated plainly in [docs/LIMITATIONS.md](docs/LIMITATIONS.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Reporting them as vulnerabilities is
reporting the design. (If the behaviour *differs from what those docs describe*,
that difference is in scope.)

- **A hostile operator defeats it** (`python -S`, editing `.env.sealed`, deleting
  state). The threat model assumes a *cooperative operator*; the adversary is a
  hostile *document* or *dependency*.
- **Native code / sibling processes egress around the Python guard** (grpcio's C
  core, ONNX Runtime, `ctypes`; Ollama and Docker). That is `make seal-pf`'s job
  (host `pf`), documented in ADR-0002 — and pf does not cover Docker's VM interface.
- **The air gap is a simulation, not a proof** — it demonstrates specific controls
  refused a specific probe set, on a host separately shown to have had internet.
- **The self-signed signature is not provenance**, and timestamps are local-clock.
- **Injection detection is probabilistic** — the classifier is archived and its own
  card disclaims jailbreaks and non-English; the FPR ceiling is a known, tracked gap
  (`docs/metrics/candidates/` — the whole field, incl. Prompt Guard 2, was swept).
- **Presidio recall is <100%**, and `ingest_mode=raw` stores real PII at rest in the
  vector store (protected by loopback + filesystem perms + FileVault, not a guardrail).

## Automated hardening in CI

Every push runs `make audit-deps` (`pip-audit` CVE gate) and `make sast` (bandit
over `src/sagp`); dependencies and pinned Actions are watched by Dependabot. Deeper
SAST via **CodeQL** is available if the repository enables GitHub Advanced Security
or is made public — this repo is private, so bandit is the SAST that gates today.
