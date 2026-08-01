# What this does not prove

The honest boundary of every claim in this repository. Each numbered item states the conclusion a
reader would reasonably but wrongly draw, what is actually true, and what it would take to close the
gap.

This document exists because the failure mode of a compliance-themed system is not a crash — it is a
confident sentence in a slide deck that nobody checks. "Air-gapped, with PII masking and injection
blocking" is exactly the kind of sentence that survives four re-tellings and arrives at an auditor
stripped of every qualifier that made it true. So the qualifiers are written down first, in their own
file, linked from the first paragraph of the [README](../README.md), before the quickstart, before the
architecture diagram, before anything that could be mistaken for a guarantee. Understating is cheap.
Overstating, in this domain, is the harm itself.

The numbering matches [BLUEPRINT.md §13](BLUEPRINT.md) exactly. Items are ordered as they appear there,
not by severity.

---

## The five that must travel with every claim

Twenty items is more than a reader carries away. These five are the ones that change what a sentence
about this system *means*, so they are repeated wherever they are relevant and are restated in full
below. If you quote this project anywhere, quote these with it.

1. **`ingest_mode=raw` — the vector store holds UNMASKED PII at rest.** `data/qdrant/` contains real
   document text. It is protected by loopback binding, filesystem permissions and FileVault; **no
   guardrail sits in that path**. (Item 11.)
2. **The injection model is archived and its own card disclaims two whole classes.**
   `protectai/deberta-v3-base-prompt-injection-v2` is unmaintained, and its model card states verbatim
   that it **does not detect jailbreak attacks** and does not handle **non-English** prompts. (Item 9.)
3. **Native code bypasses the Python egress guard.** `grpcio`'s C core, ONNX Runtime and anything
   reached through `ctypes`/`cffi` can call `connect(2)` without entering CPython's socket layer — and
   Ollama and Docker are separate processes outside both guard layers entirely. (Items 2 and 3.)
4. **The evidence signature is self-signed**, by a key generated on the very host it attests to, with
   local-clock timestamps. Not attestation, not non-repudiation. (Items 5, 6 and 7.)
5. **The guardrail metrics are measured; the performance numbers are not.** M6 measured the guardrail
   corpus (injection headline recall 1.0 and PII recall 1.0 clear their floors; precision 0.81 and benign
   FPR 0.32 miss theirs — OPEN gaps) and the injection classifier's RSS (0.30 GB, FP32). But **no latency
   figure and no RAM total** in this repository is a measurement — each is an estimate or a profile-specific
   projection. (Item 18.)

---

### 1. It does not prove the machine cannot reach the internet

**Wrongly inferred:** "The box is air-gapped."
**Actually true:** The strongest claim the design supports is that a specific set of software controls
was demonstrated to refuse a specific set of egress probes, each paired with a negative control, on a
host separately shown to have working internet moments earlier. **That demonstration has now been run
(M13):** `make verify-online` completed a real TCP handshake to `1.1.1.1:443` in 6.58 ms unguarded and
then raised `EgressViolation` under enforce, and `make verify`'s nine offline assertions pass. What has
**not** been produced is a green air-gap `PASS` verdict — on this deliberately-unsealed dev host the
verdict is `INVALID` by design (invariant 13), and the demonstration earns only the narrow claim above.
The host retains a Wi-Fi radio, Thunderbolt and Ethernet ports, Bluetooth, and USB NIC support. What
this is designed to be is a rigorous, reproducible, self-auditing **simulation** of an air gap, honest
about which of those two words applies. It is never a proof.
**To close it:** Physical removal or destruction of every network interface, in a controlled facility,
with the removal itself attested by someone other than the operator.

### 2. Native code bypasses the Python guard

**Wrongly inferred:** "Nothing in this process can open a socket."
**Actually true:** `grpcio`'s C core — a hard dependency of `qdrant-client`, present even in REST mode
— along with ONNX Runtime and anything reached through `ctypes` or `cffi`, can call `connect(2)`
without entering CPython's socket layer or emitting a PEP 578 event. `HF_HUB_DISABLE_XET=1` and the
two-virtualenv design close the specific instances we ship; they do not close the category.
**To close it:** `make seal-pf`, and only for UID-owned TCP/UDP. Fully closing it needs kernel-level
filtering the application cannot install for itself, or a host with no route at all.

### 3. Processes not started by the guarded interpreter are uncovered

**Wrongly inferred:** "The guard covers the whole system."
**Actually true:** The Ollama server, the Docker daemon, and anything an operator runs in another
terminal sit outside both guard layers. `pf` covers Ollama. `pf` does **not** cover Docker, whose
traffic leaves through a root-owned VM interface.
**To close it:** A host-level default-deny firewall managed outside the repository, plus running the
model runtime under the same guarded supervision — neither of which this template installs for you.

### 4. A hostile operator defeats it trivially

**Wrongly inferred:** "The controls are enforced against everyone with access."
**Actually true:** Editing `.env.sealed`, running `python -S`, deleting `.airgap/state.json`, or
re-signing the manifest with a fresh key each defeats the entire mechanism in seconds. The threat model
assumes a **cooperative operator** and a possibly-hostile *dependency* or *document*.
**To close it:** Two-person integrity, separation of the signing key from the operating account, and
mandatory access control enforced by something the operator cannot edit.

### 5. The signature is self-signed

**Wrongly inferred:** "The manifest is attested."
**Actually true:** The Ed25519 key is generated on the very host it attests to. It proves continuity
and tamper-evidence for one key holder. It is not third-party attestation and it is not hardware-rooted.
**To close it:** An offline CA or transparency log, or a key held in an HSM/TPM whose private half
never exists in host memory.

### 6. Timestamps are local-clock

**Wrongly inferred:** "The evidence report proves *when* something happened."
**Actually true:** No RFC 3161 timestamp authority is reachable offline. The hash chain makes
reordering and deletion detectable; it does **not** make backdating detectable.
**To close it:** A trusted timestamping service reachable through a controlled one-way path, or a
hardware clock the operator cannot set.

### 7. The audit log is tamper-evident, not tamper-proof

**Wrongly inferred:** "The audit log is non-repudiable."
**Actually true:** Anyone with write access can rebuild the chain from any point, unless the head
digest has already been exported off-box. The head digest is produced by `make audit-verify`; recording
it off-box is a *manual* operator step documented in `OPERATIONS.md` §2 and is **not automated**. Do not
use the word non-repudiation about this system.
**To close it:** Implemented, scheduled, verified export of the ledger head to independent storage —
plus a WORM sink for the events themselves.

### 8. Hashes prove identity, not safety

**Wrongly inferred:** "The artifacts are verified, therefore trustworthy."
**Actually true:** A matching sha256 proves the artifact is byte-identical to what the publisher
served. It says nothing about whether the artifact is backdoored, nor whether the classifier is any
good at its job.
**To close it:** Signed provenance (Sigstore/cosign, SLSA attestation), reproducible builds, and an
independent evaluation of the model itself — see item 16.

### 9. Injection detection is probabilistic, and the model is archived

**Wrongly inferred:** "Prompt injection is blocked."
**Actually true:** `protectai/deberta-v3-base-prompt-injection-v2` is unmaintained, and its own model
card states verbatim that it **does not detect jailbreak attacks** and does not handle non-English
prompts. The heuristic rule table carries that load imperfectly. There is no "solved" state, and the
metric floors (recall ≥0.90, precision ≥0.85, benign FPR ≤0.10) are **build-gate targets, not
guarantees**. They have now been measured at M6 — headline recall **1.0** clears its floor, but precision
**0.81** and benign FPR **0.32 miss** theirs (both OPEN `known_gaps`) — and a passing recall against a
self-authored corpus is a regression signal, not a guarantee ([EVALUATION.md](EVALUATION.md) §10).
**To close it:** Nothing closes it. Reduce it with a maintained classifier, ensembling, per-technique
recall reporting (jailbreak and indirect families reported separately, never averaged), and continuous
red-teaming against the deployed corpus.

### 10. Presidio recall is not 100%

**Wrongly inferred:** "PII is removed before the model sees it."
**Actually true:** Names outside the spaCy training distribution, PII in non-English or Indic scripts,
PII in tables and OCR noise, and novel identifier formats will be missed. Masking is a risk-reduction
control, not a guarantee. **No PII recall floor is asserted for Devanagari or transliterated names** —
that evaluation does not exist yet (**OQ-9**).
**To close it:** A labelled evaluation set built from the real corpus (100–200 examples minimum),
per-entity recall floors including the scripts actually in use, and custom recognizers for every
in-house identifier format.

### 11. `ingest_mode=raw` stores real PII in the vector store

**Wrongly inferred:** "The corpus on disk is de-identified."
**Actually true:** Chunk text is stored **unmasked** and masked only at retrieval, because masking at
ingest collides placeholders across identities and destroys retrieval against raw queries. The stored
corpus is protected by loopback binding, filesystem permissions, and FileVault — not by the guardrail.
Copying `data/qdrant/` off the box leaks the corpus with no control in the path.
**To close it:** Full-disk or per-collection encryption with keys held outside the host, plus
monitored, restricted access to the storage directory. Masked-at-ingest is not the answer; it was
evaluated and rejected.

### 12. The vault is memory-only and unencrypted while resident

**Wrongly inferred:** "The placeholder mapping never exists in a recoverable form."
**Actually true:** `vault.clear()` drops references, but Python strings are immutable and interned, so
**bytes are not scrubbed from the heap**. A core dump or a memory scraper recovers the mapping.
**To close it:** `ulimit -c 0`, no co-located untrusted processes, and — for a real fix — holding the
mapping in a mutable buffer that can be zeroed, in a process with memory protections the interpreter
does not offer.

### 13. Multi-turn conversation is unsupported

**Wrongly inferred:** "Split-payload attacks across turns are defended."
**Actually true:** The endpoint is single-turn by design because the vault is request-scoped; a
`messages` array of length greater than one is rejected with 400 `UNSUPPORTED`. Cross-turn attacks are
not defended — they are structurally impossible only because turns do not exist.
**To close it:** Conversation-scoped identity resolution and a vault with a defined lifetime and
eviction policy. Deferred to v2, deliberately.

### 14. Rehydration returns real PII to a shared bearer token

**Wrongly inferred:** "Reveal is access-controlled."
**Actually true:** `pii:reveal` is carried by a second bearer token on loopback, with no user identity,
no RBAC, and no TLS. That is adequate for a single-tenant sealed box and inadequate for anything else.
**To close it:** Per-user identity, an authorization model, mutual TLS or an authenticated local
socket, and an audit trail that names a human rather than a token.

### 15. No groundedness or hallucination scoring

**Wrongly inferred:** "Cited answers are verified against the sources."
**Actually true:** The citation validator performs an **out-of-range check on markers** and nothing
more. It cannot detect a fact attributed to the wrong supplied block, a fabricated fact carrying a
valid-looking citation, or a citation planted inside the source document itself.
**To close it:** An entailment or attribution model scoring each claim against its cited span — which
is a second model, a second RAM budget, and a second set of failure modes.

### 16. No provenance beyond hashes

**Wrongly inferred:** "The supply chain is verified."
**Actually true:** There is no Sigstore or cosign verification, no SLSA attestation, and no signed
SBOM. `pip download` fetches whatever the index serves; `--require-hashes` protects the *second*
install, not the first. Trust-on-first-use is the actual model.
**To close it:** Verify upstream signatures at fetch time, generate and sign an SBOM, and cross-check
hashes against an independently obtained source before the first install rather than after it.

### 17. Denial of service by resource exhaustion is largely unmitigated

**Wrongly inferred:** "Rate limiting protects availability."
**Actually true:** On 8 GB, a concurrent burst OOMs before the rate limits bite. One uvicorn worker
plus `anyio.CapacityLimiter(2)` is the whole defence.
**To close it:** More memory, admission control ahead of the model runtime, per-principal queueing
with backpressure, and a hard cgroup/`ulimit` boundary around each component.

### 18. The guardrail metrics are measured; latency and RAM are not

**Wrongly inferred:** "The latency and RAM numbers are measured." / "A cleared floor proves the system is safe."
**Actually true:** Provisioning has run (M1) and the guardrail corpus has been evaluated (M6), so *some*
numbers are now measured: the injection classifier's session RSS is **0.30 GB** (measured; **FP32** —
INT8 dynamic quant inverts this DeBERTa-v3, **OQ-1** and **OQ-2** resolved), the embedding parity gate
passed at **1.6e-07**, and the M6 guardrail metrics are real (recall and PII floors met; precision 0.81
and benign FPR 0.32 below target — OPEN gaps). But **every latency figure remains an ESTIMATE**, and
every derived RAM total remains a **PROJECTION** that depends on which profile you assume — **6.75 GB for
the embedded profile, 7.60 GB under `PROFILE=demo`** — so a RAM figure quoted without naming its profile
is meaningless. And a measured floor is still not safety: the corpus and the defence share an author
([EVALUATION.md](EVALUATION.md) §10), so a cleared floor is a regression signal, not a security result.
The structural conclusions — guardrail overhead is a small fraction of generation time, and the injection
classifier dominates the guardrail budget — are robust to a 2–3× error. The absolute latency/RAM numbers
are not.
**To close it:** M6 delivered the guardrail metrics; full latency and the RAM budget still await a
measured M13 pass. Measurements replace estimates, and every marker in these documents is removed only
when a number behind it has actually been observed.

### 19. `docker exec` egress tests measure the Linux VM, not macOS

**Wrongly inferred:** "The container cannot reach the internet on this host."
**Actually true:** Whether `enable_ip_masquerade: "false"` blocks egress on Docker Desktop is
**untested** (**OQ-5**) — the daemon is not running, and Docker Desktop containers egress through a
userland VM proxy rather than a host MASQUERADE rule. Whether `internal: true` can coexist with a
published loopback port is likewise untested (**OQ-4**). Do not report either as PASS on the strength
of a documentation page.
**To close it:** The Phase-0 spike, `make spike-docker`, whose result is to be recorded in ADR-0002 —
which stays **Proposed — blocked on that spike** until it runs — plus the second prober attached to
`sagp_vec_noegress`, the network Qdrant actually runs on. Only that prober's result may be cited for
the production path. Until the spike runs, the Docker path's isolation is **untested**, never
"isolated".

### 20. This is not a substitute for a regulated enclave

**Wrongly inferred:** "This meets the bar for classified or regulated isolation."
**Actually true:** It meets none of it. See the comparison below.
**To close it:** Facilities, hardware, and process controls that no repository can ship.

---

## Compared with a genuinely regulated enclave

| Control in a regulated enclave | What it provides | What this repository has instead |
|---|---|---|
| **Data diode** | Physically unidirectional transfer; egress is impossible, not merely refused | A software guard on one interpreter, plus optional `pf`. Bidirectional hardware remains present |
| **Cross-domain guard** | Independently accredited, inspected transfer between classification levels | Nothing. Transfer is an operator copying files during an unseal window |
| **Hardware attestation** | A root of trust outside the software being attested | A self-signed Ed25519 key generated on the attested host (item 5) |
| **TPM-measured boot** | Every stage from firmware upward measured into hardware registers | A sha256 manifest verified in `full` mode by the same userspace process it protects |
| **HSM** | Keys that never exist in host memory in plaintext | Key files at mode 0600 on the host filesystem |
| **Two-person integrity** | No single individual can seal, unseal, or sign alone | `make unseal REASON="…"` — one person, one command, one log line (item 4) |
| **Write-once transfer media** | Import media that cannot be re-written after use | `pip download` and `snapshot_download` over the ordinary internet (item 16) |
| **SCIF** | Physical access control, TEMPEST shielding, and no uncontrolled radios in the space | A laptop on a desk with its Wi-Fi radio switched off in software |

The right way to describe this system is: *a reproducible, self-auditing template for building isolated
LLM infrastructure, whose controls have been demonstrated individually against paired negative controls
(M13) — a demonstration, never a proof — and whose gaps are enumerated above.* Every sentence beyond
that is a claim someone will eventually have to defend.

Section 5 of [THREAT_MODEL.md](THREAT_MODEL.md) carries the full version of this comparison.
