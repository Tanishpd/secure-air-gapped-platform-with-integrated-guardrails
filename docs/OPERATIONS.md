# Operations

Day-2 operations for a sealed `sagp` host: key custody and rotation, the one manual step that makes the
audit chain mean anything, retention, model rotation, backup and restore, monitoring, and where to go when
something breaks. Phase-by-phase procedures live in the [Air-gap runbook](AIRGAP_RUNBOOK.md); this document
covers what you do between provisioning runs.

> **Status, 2026-07-27.** The repository is documentation only. No `src/`, `scripts/`, `config/`, `tests/`
> or `Makefile` exists, and nothing described here has been executed. Every command, file, gate and signal
> named below is a specification of what M0–M15 must build, not a report of an operating system.

---

## 1. Secrets

All five secrets are generated once, by `scripts/provision/09_secrets.py`, during step A9 of PROVISION.
None is ever printed to a terminal or written to an audit record.

| Name | Generator | Location | Mode | What breaks on rotation |
|---|---|---|---|---|
| `SAGP_API_TOKEN` | `09_secrets.py`, CSPRNG | `.env` | `0600` | Every client holding the old token gets **401** on `chat` and `ingest`. No data impact; no restart of Ollama or Qdrant needed. Restart the app so `Settings` re-reads it. |
| `SAGP_API_TOKEN_REVEAL` | `09_secrets.py`, CSPRNG | `.env` | `0600` | Same, for the `pii:reveal` scope only. Callers lose rehydration (C23) and fall back to receiving `<PERSON_1>`-style placeholders — a **degradation, not an error**, which makes it easy to miss. |
| Audit HMAC key | `09_secrets.py`, CSPRNG | `.env` | `0600` | Chain verification (`chain_digest`, sha256 over record bytes) **still passes** across the boundary. Any HMAC'd token derived from this key stops matching its pre-rotation counterpart, so cross-record correlation breaks at the rotation point. Append a `key_rotation` record so an auditor can see *why* correlation stops rather than inferring tampering. |
| PII pepper | `09_secrets.py`, CSPRNG | `.env` | `0600` | `pii_token_hmacs` — `HMAC(key, f"entity:{type}\x1f{normalize(type,value)}")` — change for the same entity. You permanently lose the ability to answer "did this same email appear before the rotation?" That is the entire purpose of the field. Rotate only for cause. |
| Ed25519 manifest keypair | `09_secrets.py` | private: `.airgap/keys/manifest_ed25519`<br>public: `.airgap/keys/manifest_ed25519.pub` (**committed**) | `0600` / `0644` | Every previously issued `MANIFEST.json.sig` and every signed `EVIDENCE-*.json` becomes unverifiable under the new key. You must re-sign the manifest (re-run step A10) and commit the new public key. **Archive the old public key with the old evidence** or the historical proofs become unreadable. |

**Rules that apply to all five.**

- Rotation of anything except the two API tokens requires an [`make unseal REASON="..."`](AIRGAP_RUNBOOK.md#6-re-provisioning-the-controlled-reconnection)
  cycle, because re-signing the manifest is a provisioning step.
- Verify modes after any change: `ls -l .env .airgap/keys/` — `.env` and the private key must be `0600`,
  `audit/` must be `0700`.
- Never echo a secret. `09_secrets.py` prints names and destinations only; a printed value is a defect.
- Rehydration authenticates a **shared bearer token on loopback** — no user identity, no RBAC, no TLS.
  Adequate for a single-tenant sealed box, inadequate for anything else. Treat `SAGP_API_TOKEN_REVEAL` as
  the most sensitive of the five.

**OPEN QUESTION.** The BLUEPRINT specifies `audit/hashing.py` as exposing `hmac_token` (domain-separated),
`sha256_hex`, and `chain_digest`, and separately lists both an audit HMAC key and a PII pepper. It does not
state which of the two keys `pii_token_hmacs` is derived from. Resolve this at M2, before the audit spine
is written, and correct the two middle rows of the table above to match.

---

## 2. The daily off-box step

**One manual action, once a day. It is the only thing that makes the hash chain worth having.**

```bash
make audit-verify
# ... walks audit/*.jsonl; prints, on success:
#     AUDIT CHAIN OK   records=<N>   head_seq=<N>   head_digest=<sha256>   as_of=<UTC>
```

Record `head_seq`, `head_digest`, and the UTC timestamp somewhere the sealed host **cannot write to**. On an
offline box the realistic options are: written into a paper logbook, typed into a ticket on another machine,
or read aloud to a second operator who records it. Also capture `evidence/ledger.jsonl`'s head after any
`make proof`.

**Why this is not optional.** The chain links each audit record to its predecessor, so deleting or reordering
records is detectable — *by anyone who knows what the chain looked like before*. An attacker with write
access to `audit/` does not have to break the chain: they rewrite the records they dislike and recompute
every link from that point forward. `make audit-verify` then returns green. The log is tamper-**evident**,
not tamper-**proof**, and the property only holds against an attacker who lacks write access.

An exported head digest changes that. It is a commitment, made at a known time, to the entire history up to
that point. Any rewrite of any record at or before `head_seq` produces a different digest, and the mismatch
is visible to anyone holding the export. Without exports, the chain proves nothing an attacker with write
access cannot manufacture.

**Related honest limits:** timestamps are local-clock — no RFC 3161 timestamp authority is reachable
offline, so the chain makes reordering and deletion detectable but **not** backdating. The signature is
self-signed with a key generated on the host it attests to. Do not describe any of this as non-repudiation.

**If a comparison fails**, go to [Runbook §7.3](AIRGAP_RUNBOOK.md#73-audit-chain-break).

---

## 3. Log rotation and retention sweep

`audit/sink.py` writes append-only JSONL with `fsync`, `0600` file mode, `0700` directory mode, and **daily
rotation with a carry-over record** — the new day's first record links to the previous day's head, so the
chain crosses file boundaries. Rotation is automatic; nothing external should touch these files.

**Do not** point `newsyslog`, `logrotate`, or any compression job at `audit/`. Rewriting or recompressing a
file in place breaks the chain and destroys the evidence you rotated it to preserve.

Weekly:

```bash
du -sh audit evidence data/qdrant
ls -l audit/ | tail -10          # confirm one file per day, all 0600
make audit-verify                # confirm the chain crosses the rotation boundaries
```

**Retention sweep.** Retention periods for the audit log, the vector store, private documents, and the
evidence ledger are defined — with their GDPR-vs-HIPAA justification — in the retention table in
[Compliance](COMPLIANCE.md). Before any sweep:

1. Confirm the period against that table. Audit and evidence data routinely outlive the system.
2. Export the current head digest (§2) so the surviving history remains anchored.
3. Copy anything being retained off-box and verify the copy with `make audit-verify` against the copy.
4. Only then delete. Record the sweep — the dates removed and the head digest at the time — as a new event,
   so the ledger explains its own gap rather than merely having one.

Erasure requests against the corpus are served by deleting the source document by `doc_sha256`
(`delete_by_source`), which removes its chunks from the main collection. `ingest_mode=raw` means the vector
store holds real personal data; deletion there is the erasure mechanism, not masking.

---

## 4. Model rotation

Changing any pinned model revision — the injection classifier, the embedder, the spaCy pipeline, or the
Ollama tag — is a **full unseal → provision → re-seal cycle**. There is no in-place path, and this is by
design, not an oversight:

- the revision lives in `artifacts.lock`, and every file it names is hashed into `MANIFEST.json`;
- the boot sequence runs **full** manifest verification, so a swapped file is a startup failure;
- a new classifier must pass `07_gates.py` (tokenizer parity, INT8 parity with **zero label flips**,
  measured RSS ≤ 0.35 GB) before anything can be sealed;
- a new embedder invalidates the whole index — `embed_model` and `embed_revision` are written into every
  point payload, and a query-time mismatch is a hard error rather than a silent recall collapse.

Procedure:

1. `make unseal REASON="rotate embedder to <repo>@<sha>"`, with dual control (see the runbook §6).
2. Edit `artifacts.lock` with the new repo ID **and pinned commit SHA**. Never track a branch.
3. Update `requirements.*.lock` if the change pulls a new package, and write the ADR **in the same change** —
   CLAUDE.md §6 ("Where things live") requires `artifacts.lock`, the lockfiles, `MANIFEST.json`, and an ADR
   to move together. That rule is a §6 table row, not one of the 13 numbered invariants in CLAUDE.md §2.
4. Reconnect, `make provision`. Read the step A7 gate output carefully; a new classifier is exactly the case
   the gates exist for.
5. `make eval`. Any metric more than 2pp below the baseline in `docs/metrics/latest.json` fails the build.
   That file **does not exist yet** — it is produced by the first `make eval` at M6 — so until M6 there is
   no baseline and only the absolute floors ([Evaluation](EVALUATION.md) §5, which are build-gate targets
   rather than measurements) apply. If the new model is genuinely better, commit the new baseline; if it is
   worse, that is the answer.
6. **If the embedder changed, re-ingest everything.** Old points carry the old `embed_revision` and will not
   be queried. Drop and rebuild the collections.
7. `make verify-online`, `make seal`, full physical disconnect, `make proof`.

Rotating **only** the Ollama tag (for example 3B → 1B under the FP32 fallback ladder) still requires the
cycle, because the model blob is manifested — but it does not invalidate the index.

---

## 5. Backup and restore

Take a **cold** backup: the app stopped, Qdrant stopped, Ollama stopped. A copy of `data/qdrant/` taken
while the store is live is not guaranteed consistent.

```bash
# app, qdrant, ollama all stopped
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
tar -czf "/Volumes/backup/sagp-$STAMP.tgz" \
    "data" "audit" "evidence" ".airgap/state.json" "models/MANIFEST.json"
shasum -a 256 "/Volumes/backup/sagp-$STAMP.tgz" | tee "/Volumes/backup/sagp-$STAMP.sha256"
```

| Included | Why |
|---|---|
| `data/` | the vector store and private documents — **contains real personal data** under `ingest_mode=raw` |
| `audit/` | the hash-chained ledger |
| `evidence/` | signed reports and `ledger.jsonl` |
| `.airgap/state.json` | phase, `seal_generation`, `unseal_history` |
| `models/MANIFEST.json` | so the restored state can be checked against the artifacts |

**Excluded on purpose:** `models/` weights, `vendor/` wheels, and `.venv*` — all reproducible from
`artifacts.lock` and the lockfiles, and together they are the bulk of the disk. `.env` and
`.airgap/keys/manifest_ed25519` are excluded from this command deliberately; back the secrets up
**separately**, encrypted, with a different custody path from the data they protect.

The backup medium inherits the sensitivity of `data/`. Encrypt it. A backup tarball copied off the box is
the same disclosure as copying `data/qdrant/` off the box — no guardrail sits in that path.

**Restore verification** — a restore is not complete until all four checks pass:

```bash
shasum -a 256 -c "/Volumes/backup/sagp-<stamp>.sha256"   # 1. the archive is intact
make verify-manifest                                     # 2. models/ still matches the restored MANIFEST
make audit-verify                                        # 3. the chain verifies end to end
#                                                        # 4. head_digest matches your off-box export (§2)
```

Then confirm `.airgap/state.json` reports the `seal_generation` you expect, and run `make smoke`. A restore
that silently rolls `seal_generation` backwards has reintroduced a configuration you already retired.

---

## 6. Monitoring

There is no metrics exporter and no external monitoring system — the box is offline. These are the signals
to check on a schedule, and what each one means.

| Signal | Where | Watch for |
|---|---|---|
| RSS per component | `GET /readyz` (ONNX sessions, spaCy pipeline, Presidio registry, vector store); `ollama ps` for the runner | App process above **1.40 GB** is the refuse-to-boot gate; system projection above 90% of physical RAM also refuses. Rising `Swapouts` in `vm_stat` → [Runbook §7.6](AIRGAP_RUNBOOK.md#76-oom--swap-thrash). |
| Egress violation counter | `GET /airgap/status` → `python_egress_attempts_blocked` | **Any increase is an incident**, even though the attempt was blocked. Something in-process tried to reach the network. Note the field is named for what it measures — it counts *Python-layer* attempts, and cannot see native or external-process egress. |
| Rate-limit near-miss alarm | `app/ratelimit.py` burst alarm; audit records | Repeated near-misses without 429s are a client about to be throttled, or an attacker pacing themselves just under the limit. |
| Quarantine growth | `GET /v1/admin/quarantine`; point count in `docs_quarantine` | Steady growth is normal on a poisoned or noisy corpus. A **step change** after one ingest means that document needs [Runbook §7.4](AIRGAP_RUNBOOK.md#74-suspected-poisoned-document). |
| Audit write latency | per-stage timings in the audit record; request p95 | Every request `fsync`s before responding, and an audit write failure returns **503 with the response withheld**. Growing write latency shows up as whole-request latency and is usually disk pressure. |
| Refusal rate | `decision="refuse_insufficient_context"` in audit records | A rising rate means retrieval is not finding strong hits (STRONG = 0.50) — usually an empty, stale, or over-quarantined collection. |
| Block rate and its mix | `/v1/admin/incident/{id}` | Blocks are uniform 400s to the client by design; only the audit record says which detector fired. A shift in the mix is the earliest signal that thresholds or the corpus need attention. |

**Note on p50/p95 targets: there are none yet.** All latency figures in the source design are ESTIMATES and
no benchmark has been run on this M2 — and the same holds for every other number: no guardrail metric, RAM
figure, recall number or accuracy figure anywhere in this repository has been measured. RAM projections are
profile-specific (6.75 GB embedded, 7.60 GB demo/Docker, against an 8 GB ceiling) and both are projections.
Establish your own baseline over the first week of real traffic and compare against that, not against a
number from a document.

---

## 7. Incident response

Detailed, numbered procedures are in the runbook. Use this table to get to the right one quickly.

| Symptom | Procedure |
|---|---|
| `python_egress_attempts_blocked` increased; unexplained network activity | [Runbook §7.1 — suspected egress](AIRGAP_RUNBOOK.md#71-suspected-egress) |
| `make serve` refuses to boot; manifest verification failed | [Runbook §7.2 — manifest mismatch](AIRGAP_RUNBOOK.md#72-manifest-mismatch) |
| `make audit-verify` reports `ok=False`, or the head does not match your export | [Runbook §7.3 — audit chain break](AIRGAP_RUNBOOK.md#73-audit-chain-break) |
| A document produced instruction-like model behaviour, or quarantine jumped | [Runbook §7.4 — suspected poisoned document](AIRGAP_RUNBOOK.md#74-suspected-poisoned-document) |
| Boot self-test refuses to start; gate failure on re-provision | [Runbook §7.5 — INT8 parity regression](AIRGAP_RUNBOOK.md#75-int8-parity-regression) |
| Stalls at the head of each request; rising `Swapouts` | [Runbook §7.6 — OOM / swap thrash](AIRGAP_RUNBOOK.md#76-oom--swap-thrash) |

**Escalation.** There is no on-call rotation to page and no vendor to call — this is a single-tenant offline
box. Escalation means people, in this order:

1. **The operator on duty** contains: stop the app, do not reconnect the network, do not delete anything.
2. **The second operator** (the dual-control partner from the unseal procedure) independently confirms the
   finding before any destructive action. A single operator should not both discover and remediate an
   incident affecting the audit log or the manifest.
3. **The data owner** is informed for anything touching `data/` or a PII disclosure, because
   `ingest_mode=raw` means the vector store holds real personal data and any copy of it is a disclosure.
4. **Compliance / legal** for anything with a notification obligation. See
   [Compliance](COMPLIANCE.md) for the GDPR Art. 33 pointer; this document is not legal advice.

**Evidence preservation** — do this before remediating, every time:

1. Capture `GET /airgap/status`, `GET /readyz`, `lsof -i -n -P`, and `vm_stat` to timestamped files.
2. Export the current audit head digest (§2) **before** anything else writes to `audit/`.
3. Copy `audit/`, `evidence/`, and `models/MANIFEST.json` to read-only or write-once media.
4. Run `make proof` if the system is still in a state where the verdict means anything, and keep the report
   even if the verdict is `INVALID` — *especially* then. An `INVALID` verdict recorded at incident time is
   evidence; a missing one is a gap.
5. Do not regenerate the manifest, truncate the ledger, or re-seal until the evidence is off the box. Every
   one of those actions destroys the record of what happened.

Record the incident with: UTC time discovered, `seal_generation`, manifest `root_hash`, audit head digest at
discovery, which of the six procedures was followed, and who performed and who verified each step.

---

**See also:** [Air-gap runbook](AIRGAP_RUNBOOK.md) · [Threat model](THREAT_MODEL.md) ·
[Guardrails](GUARDRAILS.md) · [Compliance](COMPLIANCE.md) · [Limitations](LIMITATIONS.md) ·
[Blueprint](BLUEPRINT.md) · [README](../README.md)
