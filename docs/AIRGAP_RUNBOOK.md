# Air-Gap Runbook

Operator checklists for taking `sagp` from a clean host to a sealed, verified, offline system — and for
running it, re-provisioning it, and responding when something breaks. Every number not measured on this
host carries an explicit `(ESTIMATE)` or `(UNVERIFIED)` marker; see [Limitations](LIMITATIONS.md) for what
this runbook does **not** prove.

> **Status, 2026-08-01 — the targets exist and were exercised; the seal itself was not.** M0–M14 are
> complete: `src/`, `tests/`, `scripts/`, `config/`, the `Makefile`, `docker-compose.yml` and
> `docs/metrics/latest.json` all exist, 258 tests pass, and `make smoke` reports 14/14. Provisioning ran
> at M1 (models fetched at pinned revisions, gates run, `MANIFEST.json` signed) and the online negative
> control ran live at M13. **What has NOT happened:** a real `make seal` plus physical disconnect (this
> dev host is deliberately kept in `PROVISION`), and the host-specific targets `seal-pf`, `ollama-up`,
> `up`, `ingest` and `query`, which are deferred. Every **duration** below is still an `(ESTIMATE)` — no
> provisioning run was timed — and every **RAM total** is a projection; those markers stand.

Repo root (note the spaces — quote it everywhere): `ROOT="/Users/tanishpd/Desktop/Secure Air-Gapped Platform with Integrated Guardrails"`

---

## 0. The phases and the one-way door

The lifecycle is a state machine in `.airgap/state.json`, enforced by `src/sagp/netguard/phase.py`, which
every Make target imports before doing anything.

```
BOOTSTRAP ──▶ PROVISION ──▶ OPERATE
                  │             │
                  ▼             ▼
               VERIFY        VERIFY
        (online negative   (offline `make proof` —
          control)          the 9 assertions)
```

| Phase | Network | Allowed | Refused |
|---|---|---|---|
| `BOOTSTRAP` | online | `doctor`, `venvs`, `lock`, `install`, `spike-docker` | — |
| `PROVISION` | **online, required** | `provision` (01–10), `verify-online`, `eval` | `serve` on an unverified manifest |
| `OPERATE` | **offline** | `ollama-up`, `up`, `serve`, `ingest`, `query`, `verify`, `evidence`, `audit-verify`, `proof` | every `provision*` target exits **2** |
| `VERIFY` | depends on parent phase | `verify-online` (from PROVISION) · `verify` (from OPERATE) | — |

**The one-way door.** `make seal` moves the phase to `OPERATE`, and from that moment every target that
could touch the network refuses to run. Returning to `PROVISION` requires an explicit, reasoned, audited
`make unseal REASON="..."` (§6). This is deliberate: the most-expected failure mode is an operator or an
agent quietly running `pip install` on a sealed box.

**`seal_generation`** is an integer in `.airgap/state.json`, incremented by **every** `make seal`. It is the
identity of one sealed configuration, and it appears in `evidence/verify-online-<gen>.json` (which `make
seal` refuses to proceed without), in every `EVIDENCE-<gen>-<utc>.json`/`.md`, and in every record appended
to `evidence/ledger.jsonl`. Two reports with different generations describe two different systems — never
cite a proof from generation *N* as evidence about generation *N+1*.

**Refusal rules** (`netguard/phase.py`): any `provision*` target exits `2` in `OPERATE`; `seal` refuses
unless `MANIFEST.json` verifies, its signature checks, **and** `evidence/verify-online-<gen>.json` exists
with `all_probes_blocked == true`; `up`/`serve` run **full** manifest verification as a hard precondition —
a mismatch is a startup failure, not a warning; `unseal` requires `REASON=` and writes `unseal_history`.

---

## 1. Pre-provision checklist

`make doctor` performs all of these read-only and hard-fails on disk. The individual commands tell you
which one it tripped on. Do not start Phase A with an unchecked box.

- [ ] **Free disk ≥ 25 GB** — `diskutil info / | grep -i "Free Space"` (also `df -g /`). The full closure is
      ~19.6 GB (BLUEPRINT §8, includes the `llama3:8b` pull), plus ~3 GB transient for quantization, plus headroom. `doctor` hard-fails below
      `sum(artifacts.lock sizes) × 1.5 + 5 GB`.
      **Disk-constrained host (≥ 15 GB but < 25 GB free)?** Skip the optional `llama3:8b` pull at A4 — it is
      4.7 GB, it does **not** fit in 8 GB RAM at runtime anyway (§7), and skipping it drops the requirement
      to ~15 GB. This is the recommended path on the current host (22.5 GB free as of 2026-07-30). Keep `8b`
      only if you have freed to ≥ 25 GB and specifically want to reproduce the does-not-fit failure.
- [ ] **Python 3.11.15** — `~/.local/bin/python3.11 --version` → `Python 3.11.15`. The system default here
      is 3.14.6, too new for spaCy.
- [ ] **Docker running — `PROFILE=demo`/`proof` only** — `open -a Docker` then
      `docker info --format '{{.ServerVersion}}'` → `29.5.3`. Qdrant is the only vector store in this
      design. `SAGP_QDRANT_MODE=embedded` is the **default runtime backend**, chosen on RAM grounds
      (6.75 GB projected for the embedded profile vs 7.60 GB projected for the demo/Docker profile,
      against an 8 GB ceiling — both projections, neither measured), and it needs no Docker.
      `PROFILE=demo` (Docker, `qdrant/qdrant:v1.18.3-unprivileged`) is the **demonstration and proof
      path** — the network-isolation boundary this project exists to show, and the path the proof harness
      targets. It is **NOT network-isolated by compose options** — never write "isolated" — as the Phase-0
      spike below (run 2026-08-01) established when it resolved OQ-4 and OQ-5. ADR-0002 is **Accepted**.
- [ ] **Host is online** — `curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' https://huggingface.co`
      → `200`, and `ping -c1 1.1.1.1` → 0% loss. Provisioning downloads ~8.2 GB (ESTIMATE) plus the
      4.7 GB `llama3:8b` tag pulled at A4 (it **is** pulled — included in BLUEPRINT §8's totals, per
      PLAN §1), and the online negative control is *invalid* without working internet.
- [ ] **No other memory-heavy apps** — `ps -A -o rss=,comm= | sort -rn | head -15` (RSS in KB), `vm_stat`,
      and `ollama ps` → empty. 8 GB is a hard ceiling; step A6 wants ~3 GB transient.
- [ ] **FileVault on** — `fdesetup status` → `FileVault is On.` Under `ingest_mode=raw` the vector store
      holds real document text; full-disk encryption is one of the two compensating controls (the other is
      loopback binding).
- [ ] **Core dumps off** in the serving shell — `ulimit -c 0 && ulimit -c` → `0`. The PII vault is
      memory-resident and unscrubbed.
- [ ] **Bootstrap done** — `make venvs lock install`; confirm `.venv`, `.venv-provision`, and that both
      lockfiles are hash-pinned.
- [x] **Phase 0 — the Docker spike, `make spike-docker`** (`PROFILE=demo`/`proof` only; run online, in
      `BOOTSTRAP`, before Phase A). **RUN 2026-08-01** on Docker Desktop 29.5.3; it resolved two questions
      empirically, both **negatively** (evidence: `evidence/spike-docker.json`, gitignored):
      **OQ-4** — `internal: true` and an app-reachable Qdrant are **mutually exclusive**: with `internal: true`
      a published `127.0.0.1:6333` port is accepted but the host cannot reach it (http_code 000), so the
      compose file uses a **non-internal** bridge.
      **OQ-5** — `enable_ip_masquerade: "false"` does **not** block egress on Docker Desktop; on a reachable
      network TCP and DNS both reach out via the userland VM proxy, and DNS always resolves via the embedded
      resolver even on an internal network.
      **Conclusion:** the Docker path is **NOT isolated by compose options** — its egress control comes from
      the `pf` anchor (`make seal-pf`) + loopback binding, not Docker networking. ADR-0002 is now **Accepted**.
      No document may call the Docker path "isolated"; the accurate phrase is "not isolated by compose options".

---

## 2. Phase A — PROVISION (online, one-way door)

```bash
make provision    # runs scripts/provision/01..10 in order; resumable; idempotent
```

`make provision` is the supported entrypoint; the steps are described individually so you know what each
one is doing and what to do when it stops. Running a step outside `make` is a debugging aid only and its
exact invocation must match the shipped `Makefile` (**UNVERIFIED** — check before relying on it).

**Provisioning ran on this M2 at M1** (models fetched at pinned revisions, gates run, `MANIFEST.json`
signed and committed) — but it was not timed. Every duration below is therefore still an `(ESTIMATE)`
derived from artifact sizes at a nominal 20 MB/s; replace them after a timed run.

### A1 · `01_wheelhouse.sh` — offline wheel closures

```bash
pip download --require-hashes --python-version 3.11 --implementation cp \
  --abi cp311 --platform macosx_14_0_arm64 --only-binary=:all: \
  -r requirements.runtime.lock -d vendor/wheelhouse
```

Builds `vendor/wheelhouse/` (runtime) and `vendor/wheelhouse-provision/` so the sealed host can reinstall
without an index. **Expect:** a `Saved …-cp311-cp311-macosx_14_0_arm64.whl` line per package, then
`Successfully downloaded`. **Download ~2.8 GB** (0.60 runtime + 2.20 provision). **6–12 min (ESTIMATE).**
**On failure:** the near-certain cause is the platform tag — `macosx_14_0_arm64` is the real tag for torch
2.x and onnxruntime 1.28, **not** `macosx_11_0`. A `No matching distribution` for a package that plainly
exists means the tag or ABI is wrong, not the pin. Never relax `--require-hashes` or `--only-binary=:all:`;
a source build on the sealed host is what this step exists to prevent.

### A2 · `02_hf_models.py` — HuggingFace artifacts at pinned revisions

`snapshot_download(repo_id, revision=<pinned sha>, local_dir=models/hf/…, allow_patterns=[…])` for
`protectai/deberta-v3-base-prompt-injection-v2` @ `90c9989b1a342275dd0d1a95aad283c04e075671` and
`BAAI/bge-small-en-v1.5` @ `5c38ec7c405ec4b44b94cc5a9bb96e735b38267a`.

**Expect:** per-file progress, then resolved paths. Verify byte counts: classifier `onnx/model.onnx` =
**738,563,188 B**, `model.safetensors` = **737,719,272 B**, embedder `onnx/model.onnx` =
**133,093,490 B**. **Download ~1.62 GB. 3–8 min (ESTIMATE).**
**On failure:** a `401`/`403` means a repo flipped to gated — both downloaded successfully as **ungated**
at M1, so treat a new `401`/`403` as a supply-chain event, stop, and record it. A revision mismatch means `artifacts.lock` and upstream disagree;
do not "fix" it by moving to `main`. `model.safetensors` exists only so A7 can compare torch-FP32 against
ONNX-INT8; it is excluded from the runtime manifest subset.

### A3 · `03_spacy.sh` — spaCy pipelines as real pip packages

Curls three wheels to `models/spacy/`, then `pip install --no-index --no-deps` the `md` one. They must be
real packages so `spacy.util.is_package` succeeds. **Expect:** `en_core_web_md` 33,480,380 B, `sm`
12,806,118 B, `lg` 400,658,291 B, then `Successfully installed en-core-web-md-3.8.0`.
**Download ~0.447 GB. 1–2 min (ESTIMATE).**
**On failure:** re-curl the exact release URL. Never fall back to `spacy.cli.download` — it resolves a URL
at runtime and is a forbidden idea. A GitHub rate limit here is transient.

### A4 · `04_ollama.sh` — LLM weights into the repo

```bash
OLLAMA_MODELS="$PWD/models/ollama" ollama serve &
OLLAMA_MODELS="$PWD/models/ollama" ollama pull llama3.2:3b-instruct-q4_K_M
```

**Expect:** `pulling manifest` → layer digests → `success`, then a printed blob digest list that A10 hashes.
**Download 3.3 GB** — 2.0 GB (`llama3.2:3b-instruct-q4_K_M`) + 1.3 GB (`llama3.2:1b`, the parity-failure
fallback). `llama3:8b` is an **optional** pull — [PLAN](PLAN.md) §1 records it as an operator choice so
that it is one env var away — adding **4.7 GB** (8.0 GB total for this step), included in the BLUEPRINT §8
totals (lean ≈ 9.7 GB / full ≈ 19.6 GB). **On a disk-constrained host, skip it** (see the pre-provision
checklist): it does not fit in 8 GB RAM at runtime, so it is never a supported configuration — it exists
only to reproduce the does-not-fit failure. On the current host the recommended path is to **skip the 8b
pull** (22.5 GB free < the 25 GB the full closure wants).
**6–14 min (ESTIMATE), or 12–24 min (ESTIMATE) with the 8b tag.**
**On failure:** confirm `OLLAMA_MODELS` pointed inside the repo *before* the pull. A model pulled into
`~/.ollama` is outside the manifest and will make A10 and every later boot verification inconsistent.
Re-pull with the variable set; do not symlink.
**`llama3:8b` does not fit** — it projects to 9.28 GB (embedded profile; worse under `PROFILE=demo`)
against an 8 GB ceiling, a projection and not a measurement. macOS compresses and swaps
rather than OOMs, so it *appears* to work at 3–6 tok/s (ESTIMATE) while the pages evicted are the idle
guardrail models. That is a security property, not just slowness.

### A5 · `05_docker.sh` — container images (`PROFILE=demo`/`proof` only)

`docker pull` → resolve digest → `docker save -o models/docker/*.tar` for
`qdrant/qdrant:v1.18.3-unprivileged` (~70 MB compressed) and `alpine:3` (~4 MB compressed / ~8 MB uncompressed, the egress prober).
**Expect:** a resolved `sha256:` digest per image and two tarballs. **~0.16 GB on disk. 1–3 min (ESTIMATE).**
**On failure:** on the default profile, skip it — embedded Qdrant needs no image. On `demo`/`proof`, the
daemon is stopped: `open -a Docker`, wait for `docker info` to answer, retry.

### A6 · `06_quantize.py` — INT8 quantization

```python
quantize_dynamic("models/hf/injection/onnx/model.onnx",
                 "models/derived/injection-int8/model.onnx")   # DEFAULT op types
```

**Expect:** quantizer progress, then the written path and size. **Outcome on this host (OQ-2 resolved):**
INT8 dynamic quantization **inverts** this DeBERTa-v3, so the A7 parity gate rejects it and the shipped
classifier is the **FP32 ONNX** — see A7. The INT8 artifact is still produced here; it is simply not the
model that ships.
**No download. ~3 GB transient — which is why this runs before Ollama is started. 3–10 min (ESTIMATE).**
**On failure:** do **not** pass `op_types_to_quantize=["MatMul","Gather"]` — `Gather` is already in
`CommonOpsRegistry ⊂ IntegerOpsRegistry`, so passing the list *narrows* the set. If the host OOMs, close
everything and retry; nothing else should be resident.

### A7 · `07_gates.py` — **THE HARD GATE**

| Gate | Assertion |
|---|---|
| Tokenizer parity | `tokenizers.Tokenizer.from_file(…)` produces byte-identical `input_ids`/`attention_mask` to `transformers.AutoTokenizer.from_pretrained(…)` over the full 63-case corpus |
| INT8 parity | `\|Δ P(INJECTION)\| < 0.05` and **zero label flips** across the corpus, FP32 ONNX vs INT8 |
| Embedding parity | ORT + CLS pooling + L2 norm matches `SentenceTransformer("BAAI/bge-small-en-v1.5").encode(…, normalize_embeddings=True)` to `atol=1e-4` over 200 fixtures |
| RSS measurement | measured steady-state RSS of every ORT session; **fails provisioning if the classifier session exceeds 0.35 GB** |

**Expect:** four `GATE … PASS` lines each printing its measured value. **Measured on this host at M1:** INT8
parity **failed** (OQ-2 — INT8 inverts this DeBERTa-v3), so the ladder fell to **FP32 ONNX**; embedding
parity **1.6e-07** (well inside `atol=1e-4`); FP32 classifier session RSS **0.30 GB**, under the 0.35 GB
gate. These figures replace the corresponding `(ESTIMATE)` rows of the BLUEPRINT §7 RAM table.
**No download. 2–5 min (ESTIMATE).**

**This step is why `make seal` is unreachable with an unvalidated classifier.** `make provision` exits
non-zero on any gate failure, so the phase never advances, so `seal` refuses on an unverifiable manifest.
There is no flag that skips it. Do not add one.

- **Tokenizer gate fails:** stop. Dropping `transformers` from the runtime is safe *only because* this gate
  passes; a divergence means the sealed runtime tokenizes differently from the training-time tokenizer.
- **INT8 parity fails (OQ-2 — this is what happened on this host):** walk the ladder in order — INT8 →
  FP32 ONNX (kept on disk) → drop the LLM to `llama3.2:1b`. On this host the ladder stopped at **FP32**:
  its session RSS is **0.30 GB measured** (ORT mmaps the weights), the same budget INT8 would have used, so
  the FP32 fallback did **not** force dropping the 3B. Re-run `make provision`; the gate must pass on the
  configuration you intend to seal.
- **RSS gate fails (> 0.35 GB):** same ladder. Do not raise the threshold to make it pass. (The shipped
  FP32 session measured 0.30 GB, so this gate passed.)

### A8 · `08_tldextract_cache.py` — warm the Public Suffix List

Presidio's `EmailRecognizer.validate_result` calls module-level `tldextract.extract`, which fetches the PSL
over **HTTPS on first use**. On a sealed box that raises an `EgressViolation` *inside* Presidio and turns the
first email ever analyzed into a 503. This warms the snapshot into `models/tldextract/` while the network
is up. **Expect:** the cache path and a non-zero size. **< 1 MB, seconds.**
**On failure:** do not proceed to seal. Confirm `TLDEXTRACT_CACHE=<repo>/models/tldextract` is exported and
that `SealedEmailRecognizer` is built with `suffix_list_urls=()` and `fallback_to_snapshot=True`.

### A9 · `09_secrets.py` — key material

Generates `SAGP_API_TOKEN`, `SAGP_API_TOKEN_REVEAL`, the audit HMAC key, the PII pepper, and the Ed25519
manifest keypair; writes `.env` at `0600` and `.airgap/keys/` with the private key at `0600`.
**Expect:** a list of generated secret **names** and destinations. No value should ever be echoed — a
printed token is a defect; report it. **Seconds.** Custody and rotation: [Operations](OPERATIONS.md) §1.

### A10 · `10_manifest.py` — hash and sign everything

sha256 of every file under `models/` and `vendor/` → `MANIFEST.json` + `.sha256` + `.sig`.
**Expect:** file count, the `root_hash` (aliased as `manifest_hash`), and `signature: ok`. **Write the root
hash down** — it is the identity of this artifact set. **1–3 min to hash ~4 GB (ESTIMATE).**
**On failure:** "present but unmanifested" means something wrote into `models/` after hashing began —
re-run. A signature failure means the private key is missing or unreadable.

### A-post · negative control and metrics baseline

```bash
make verify-online   # NEGATIVE CONTROL — must be green BEFORE sealing (§4)
make eval            # corpus metrics -> docs/metrics/latest.json  (commit this file)
```

`make seal` refuses without `evidence/verify-online-<gen>.json` carrying `all_probes_blocked == true`.

`docs/metrics/latest.json` **exists** — first produced by `make eval` at M6. Measured headline injection
recall is **1.0** and PII recall **1.0** for the four covered entities; precision **0.81** and benign FPR
**0.32** miss their 0.85 / 0.10 targets and are tracked as OPEN `known_gaps` (medium). Those measurements
are now the regression baseline: the recall and PII floors in [Evaluation](EVALUATION.md) §5 are hard
gates, precision/FPR are regression-gated.

---

## 3. Phase B — SEAL

### B1 — Seal the software state

```bash
make seal
```

Writes `.env.sealed` and `.airgap/state.json` (`phase=OPERATE`, `seal_generation++`), installs
`.venv/lib/python3.11/site-packages/{airgap_guard.pth,airgap_guard_boot.py}`, and prints the disconnect
checklist. **Expect:** the new `seal_generation`, the manifest root hash, `guard bootstrap installed`.
If it refuses it will name the reason — manifest does not verify, signature invalid, or the online negative
control is missing for this generation. All three are correct refusals.

### B2 — What `.env.sealed` contains, and why `bin/sagp-serve` sources it

```bash
export HF_HUB_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 HF_HUB_DISABLE_IMPLICIT_TOKEN=1
export HF_HUB_DISABLE_UPDATE_CHECK=1 HF_HUB_DISABLE_XET=1 DO_NOT_TRACK=1
export HF_HOME="$PWD/models/hf-home"
export TLDEXTRACT_CACHE="$PWD/models/tldextract"
export TOKENIZERS_PARALLELISM=false PYTHONDONTWRITEBYTECODE=1
export OLLAMA_HOST=127.0.0.1:11434
export OLLAMA_MODELS="$PWD/models/ollama"
export OLLAMA_NO_CLOUD=1 OLLAMA_NOPRUNE=1 OLLAMA_ORIGINS=http://127.0.0.1
export OLLAMA_MAX_LOADED_MODELS=1 OLLAMA_NUM_PARALLEL=1 OLLAMA_MAX_QUEUE=16
export OLLAMA_CONTEXT_LENGTH=4096 OLLAMA_KEEP_ALIVE=30m
export OLLAMA_FLASH_ATTENTION=1 OLLAMA_KV_CACHE_TYPE=q8_0
export no_proxy='*' NO_PROXY='*'
unset  http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
export SAGP_ENV=prod
```

**Why a shell file sourced before exec, and not `.env`.** The `HF_*` flags are read by `huggingface_hub`
**at import time**, from the process environment. `pydantic-settings` loads `.env` *after* the interpreter
has started and after imports have run — by which point the flags are a no-op. So `bin/sagp-serve` sources
`.env.sealed` **before** it `exec`s the interpreter. That is the only supported launch path; starting
`uvicorn` by hand bypasses it. **Corrected at M0:** `huggingface_hub` *is* importable in `.venv` —
`tokenizers==0.23.1` hard-depends on it — so the flags are not belt-and-braces, they are the primary
control that keeps hub offline, alongside the egress guard. The `lifespan` assertion is therefore on
`torch`/`transformers` being un-importable (they are), not on hub; our code never imports hub (AST scan).

`.env.sealed` is **generated**. Never hand-edit it — that is one of the ways an impatient operator defeats
the entire control set.

### B3 — Optional: `make seal-pf`

**This belongs here — inside Phase 2 SEAL, immediately after `make seal` and *before* the physical
disconnect** (BLUEPRINT §6, CLAUDE.md §4). Loading the anchor while you can still reach the host over the
network is what makes a mistake recoverable.

The pf anchor at `deploy/pf/com.sagp` is the only control covering native-library and external-process
egress — `grpcio`'s C core, ONNX Runtime, `ctypes`, and the Ollama server, all outside both Python guard
layers. It covers UID-owned TCP/UDP only, and it does **not** cover Docker, whose traffic leaves via a
root-owned VM interface.

macOS `pf` is OpenBSD-4.4 era and its parser is unforgiving. **Dry-run the parse first. This is mandatory.**

The anchor ruleset (`deploy/pf/com.sagp`) is, in sketch — pass loopback, deny everything else out for
the operator UID (substitute the real uid; `id -u` on the sealed account):

```
# deploy/pf/com.sagp   — loaded into the "sagp" anchor. Loopback passes; all other egress denied for the UID.
set skip on lo0
pass  out quick inet  proto { tcp udp } from 127.0.0.1 to 127.0.0.1
pass  out quick inet6 proto { tcp udp } from ::1       to ::1
block drop out log inet  proto { tcp udp } user 501     # <- replace 501 with the sealed account's uid
block drop out log inet6 proto { tcp udp } user 501
```

`/etc/pf.conf` needs the two lines that load and reference the anchor:

```
anchor "sagp"
load anchor "sagp" from "/path/to/repo/deploy/pf/com.sagp"   # quote the path — it contains spaces
```

```bash
sudo pfctl -n -f /etc/pf.conf     # DRY-RUN PARSE — must report no errors
sudo pfctl -f  /etc/pf.conf
sudo pfctl -E
sudo pfctl -a sagp -s rules       # confirm the anchor's rules loaded
```

If the dry run reports a syntax error, **stop**. Loading a half-parsed ruleset on a machine you are about
to disconnect is how you lock yourself out of a host you cannot SSH into. Back out with
`sudo pfctl -a sagp -F rules`, then `sudo pfctl -d` if pf was previously disabled.

### B4 — Physical disconnect

The last step of Phase 2, and the only irreversible one. Do not start it until B3 has either completed
cleanly or been consciously skipped.

1. [ ] `networksetup -setairportpower en0 off`
2. [ ] Physically unplug Ethernet and any Thunderbolt / USB network adapter.
3. [ ] Turn Bluetooth off — tethering is egress.
4. [ ] No interface has a route: `ifconfig | grep -E '^[a-z0-9]+:|inet '` and `netstat -rn | head`.
5. [ ] The network is actually gone — **both must fail**:
   `ping -c1 1.1.1.1` and `curl -sS --max-time 3 https://huggingface.co`.
6. [ ] Nothing listening off-loopback:
   `lsof -iTCP -sTCP:LISTEN -P -n | grep -v '127.0.0.1\|\[::1\]'` → no rows. A non-loopback listener is an
   **invalidating condition** for any PASS verdict in §4.

---

## 4. Phase C — VERIFY

```bash
make verify        # scripts/verify_airgap.py — the 9 assertions
make evidence      # signed EVIDENCE-<gen>-<utc>.json/.md + ledger append
make audit-verify  # hash-chain walk; exit 1 on any break
make proof         # verify + evidence
```

Each assertion asserts on the **`EgressViolation` type**, never on a generic connection failure, and each
is paired with a positive control so it cannot pass for the wrong reason. All nine are written and ran at
M13: every assertion **passed** and every paired control behaved as expected — but the run's verdict was
`INVALID` by design, because this host was never sealed (see the verdicts table below).

| # | Assertion | Paired negative control |
|---|---|---|
| 1 | Guard installed; both layers report in the install receipt | — (if false, everything below is `INVALID`) |
| 2 | `socket.create_connection(("1.1.1.1",443))` → `EgressViolation` (L1 monkeypatch) | loopback echo server connects and echoes |
| 3 | `_socket.socket().connect(("1.1.1.1",443))` → `EgressViolation` (**L2 only** — L1 is bypassed by construction here, and L2 catches it — verified at M11) | `socket.create_connection(("127.0.0.1",11434))` succeeds |
| 4 | `socket.getaddrinfo("huggingface.co",443)` → `EgressViolation` | `getaddrinfo("localhost",8000)` succeeds |
| 5 | `httpx.get("https://huggingface.co")` → `EgressViolation` | `httpx.get("http://127.0.0.1:8000/healthz")` → 200 |
| 6 | `subprocess.Popen(["curl","https://example.com"])` → `EgressViolation` (PEP 578 `subprocess.Popen`) | `subprocess.Popen([ollama_path,"--version"])` succeeds (allowlisted) |
| 7 | `open("/var/run/docker.sock")` connect → `EgressViolation` (AF_UNIX deny-by-default) | an allowlisted unix path connects |
| 8 | Presidio detects `EMAIL_ADDRESS` with `len(egress.violations()) == 0` | the same call with an un-warmed PSL cache **does** violate |
| 9 | `manifest.verify(mode="full")` → `ok`, `root_hash` matches, signature valid, zero unmanifested files under `models/` | flipping one interior byte of `model.onnx` is detected at the right path |

`PROFILE=proof` adds Docker-network assertions, including a second prober on `sagp_vec_noegress` — the
network Qdrant actually runs on. **Only that second prober's result may be cited for the production path.**
The Phase-0 spike (`make spike-docker`, §1) settled both questions on 2026-08-01, **negatively**:
`enable_ip_masquerade: "false"` does **not** block egress on Docker Desktop (OQ-5 — containers egress via a
userland VM proxy, and DNS always resolves via the embedded resolver), and `internal: true` cannot coexist
with an app-reachable published loopback port (OQ-4 — the host cannot reach it, so a non-internal bridge is
used). `docker exec` probes measure Docker's Linux VM, not macOS. The Docker path is therefore **NOT isolated
by compose options** — its egress control comes from the `pf` anchor + loopback binding, never `internal:`.

### Annotated PASS output

The shape is the contract; the values are illustrative. `make verify` **has run** (M13, all nine
assertions and their controls green), but on an unsealed host it returns `INVALID` by design, so the `PASS`
transcript below remains a specimen of the output format, not a capture from this host.

```
$ make verify
[verify] phase=OPERATE  seal_generation=3  guard=enforce
[verify] manifest: mode=full  files=412  root_hash=9f2c…4ab1  signature=ok
  [1/9] guard install receipt        PASS  layers=[L1:monkeypatch, L2:audithook]
  [2/9] L1 create_connection         PASS  EgressViolation in 0.4 ms
        ↳ control: loopback echo     PASS  echoed 4 bytes           ← the guard is not blocking everything
  [3/9] L2 _socket.connect           PASS  EgressViolation in 0.3 ms ← L1 bypassed by construction; L2 caught it
        ↳ control: 127.0.0.1:11434   PASS  connected
  [4/9] DNS getaddrinfo              PASS  EgressViolation
        ↳ control: localhost:8000    PASS  resolved
  [5/9] httpx https://huggingface.co PASS  EgressViolation
        ↳ control: /healthz          PASS  200
  [6/9] subprocess curl              PASS  EgressViolation (PEP 578 subprocess.Popen)
        ↳ control: ollama --version  PASS  allowlisted, exit 0
  [7/9] AF_UNIX docker.sock          PASS  EgressViolation
        ↳ control: allowlisted path  PASS  connected
  [8/9] presidio EMAIL_ADDRESS       PASS  1 entity, egress violations=0
        ↳ control: cold PSL cache    PASS  did violate              ← proves A8 is what made it pass
  [9/9] manifest full verify         PASS  byte-flip detected at models/derived/injection-int8/model.onnx
VERDICT: PASS   python_egress_attempts_blocked=9   ledger_head=7c1a…9d02
```

**The `↳ control:` lines are the whole point.** A test that passes because the network was simply absent has
told you nothing. That is why assertion 2's control connects to loopback, why assertion 8's control
deliberately violates with a cold cache, and why `make verify-online` had to prove this host had working
internet *before* you disconnected it.

### Annotated FAIL output

```
  [3/9] L2 _socket.connect           FAIL  raised OSError(51, 'Network is unreachable'), not EgressViolation
        ↳ control: 127.0.0.1:11434   PASS  connected
VERDICT: INVALID   reason=assertion_3_wrong_exception_type
```

`OSError` instead of `EgressViolation` is the single most important failure to recognise: the connection
failed **because the network is gone**, not because a control refused it. The controls may be absent
entirely. Reconnect, re-run `make verify-online`, and find out whether the guard is installed at all.

```
  [8/9] presidio EMAIL_ADDRESS       PASS  1 entity, egress violations=0
        ↳ control: cold PSL cache    FAIL  did NOT violate
VERDICT: INVALID   reason=negative_control_8_did_not_violate
```

The assertion "passed" but its control did not fire, so the pass cannot be attributed to the PSL warm-up.
Nothing was proven.

### Verdicts

| Verdict | Meaning |
|---|---|
| `PASS` | Every assertion held **and** every paired control behaved as expected. |
| `PASS_WITH_OPEN_HIGH_SEVERITY_GAPS` | All assertions held, but a `known_gap` with `severity: high`, `status: OPEN` is recorded. Never report this as `PASS`. |
| `FAIL` | A control that should have held provably leaked — an assertion failed. |
| `INVALID` | The run proves nothing (an invalidating condition fired — see below). Do not publish it. |

**Invalidating conditions — any one forces `INVALID`:** a negative control failed; the guard is not
installed; the manifest was verified in `quick` mode (it skips every file's interior); a non-loopback
listener is present; the signature is invalid; the evidence ledger chain is broken; `SAGP_GUARD` is not
`enforce`.

---

## 5. Steady-state operations

**Start order — Ollama, then Qdrant, then the app.**

```bash
make ollama-up   # launchd plist, loopback-bound, env from .env.sealed
make up          # PROFILE=demo only: docker load + compose up qdrant
make serve       # bin/sagp-serve -> uvicorn --workers 1 --host 127.0.0.1
```

The order is not cosmetic: `make serve` runs a full manifest verification and a boot self-test that includes
reaching Ollama, so it fails its startup checks if Ollama is not up. `--workers 1` is mandatory — a second
worker means a second spaCy pipeline and a second ONNX Runtime session against the 1.25 GB of headroom the
**embedded** profile projects (0.40 GB projected under `PROFILE=demo`). Both are projections (ESTIMATE),
not measurements.

`make ollama-up` installs a loopback-bound launchd agent whose environment is sourced from
`.env.sealed`. Skeleton (`deploy/launchd/com.sagp.ollama.plist`, loaded with `launchctl bootstrap`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key>            <string>com.sagp.ollama</string>
  <key>ProgramArguments</key> <array><string>/path/to/repo/bin/ollama-serve</string></array>
  <key>EnvironmentVariables</key> <dict>
    <key>OLLAMA_HOST</key>   <string>127.0.0.1:11434</string>   <!-- loopback only -->
    <key>OLLAMA_MODELS</key> <string>/path/to/repo/models/ollama</string>
    <key>OLLAMA_ORIGINS</key><string>http://127.0.0.1</string>
    <key>OLLAMA_NOPRUNE</key><string>1</string>
  </dict>
  <key>RunAtLoad</key>  <true/>
  <key>KeepAlive</key>  <true/>
</dict></plist>
```

`bin/ollama-serve` sources `.env.sealed` before exec'ing `ollama serve`, so the plist carries only the
loopback-critical keys; quote every path (the repo path contains spaces).

**Stop order — reverse.** Stop the app (Ctrl-C `make serve`), then `docker compose down` on `PROFILE=demo`,
then `make ollama-down`. Stopping Ollama first strands in-flight requests and leaves the 120 s LLM timeout
to expire.

**Routine use:** `make ingest FILE="data/samples/employee_handbook.pdf" COLLECTION=handbook` ·
`make query Q="How many days of parental leave do I get?"` · `make smoke` (14 numbered checks).

| What | Path | Mode / note |
|---|---|---|
| Audit events (append-only JSONL, fsync'd, daily rotation) | `audit/events-YYYYMMDD.jsonl` | dir `0700`, files `0600` |
| Quarantined offending text (referenced by `incident_id` only) | `audit/` quarantine store | `0600` |
| Evidence reports | `evidence/EVIDENCE-<gen>-<utc>.json` / `.md` | signed |
| Evidence hash chain | `evidence/ledger.jsonl` | append-only |
| Vector store (embedded) | `data/qdrant/` | holds **real** document text under `ingest_mode=raw` |
| Operator documents | `data/private/` | gitignored |
| Logging config | `config/logging.yaml` | dictConfig + PII redaction filters |

**Disk watch:** `df -g /` and `du -sh models data audit evidence vendor`. `data/qdrant/` and `audit/` are the
two that grow; rotation and the retention sweep are in [Operations](OPERATIONS.md) §3.

**Memory watch:**

```bash
ollama ps                                                    # runner SIZE — validates the largest RAM row
curl -s http://127.0.0.1:8000/readyz | python3 -m json.tool  # measured RSS per component
ps -A -o rss=,comm= | sort -rn | head -10
vm_stat | grep -E 'Pageouts|Swapouts|compressor'
```

The app process gate is **refuse to boot above 1.40 GB**; a system projection above 90% of physical RAM also
refuses to boot. Non-zero and **rising** `Swapouts` is the §7.6 signal — act on it, because the pages macOS
evicts first are the idle security controls.

---

## 6. Re-provisioning (the controlled reconnection)

1. **Justify it in writing.** The reason string is permanent and lands in `unseal_history`.
   ```bash
   make unseal REASON="add pypdf 6.15.0 for CVE-XXXX-YYYY"
   ```
   This is the only way out of `OPERATE`.
2. **Dual control (recommended).** Two people: one performs the unseal, the other independently reviews the
   reason, the manifest diff, and the re-seal evidence. **The system does not enforce this** — it has no user
   identity model, only shared bearer tokens on loopback. It is a procedural control and you must run it as
   one. Record both names in the change record.
3. **Reconnect deliberately.** Re-enable exactly one interface, preferably wired. Confirm you are online and
   note the UTC time — the window between reconnection and re-seal is the exposure window and belongs in the
   change record.
4. **Re-provision.** `make provision` (resumable; only changed artifacts re-download) → `make verify-online`
   (a *new* negative control for the *new* generation) → `make eval` (any metric >2pp below
   `docs/metrics/latest.json` fails the build).
5. **Review the manifest diff before sealing** — the step people skip and should not:
   ```bash
   git diff -- models/MANIFEST.json
   ```
   For every changed row ask: did I intend this file to change? A changed `root_hash` with an unexplained
   file underneath it is a supply-chain event, not a routine update. `MANIFEST.json` is committed precisely
   so this diff exists.
6. **Re-seal and re-prove.** `make seal` (`seal_generation++`) → `make seal-pf` (§3 B3) → the full §3 B4
   disconnect procedure again →
   `make proof` under the new generation.
7. **Retire the old evidence.** Keep it as history; never cite generation *N* for generation *N+1*.

---

## 7. Incident procedures

### 7.1 Suspected egress

1. Stop the app. Do **not** reconnect the network.
2. Capture state before anything else changes it:
   ```bash
   curl -s http://127.0.0.1:8000/airgap/status | tee "/tmp/airgap-status-$(date -u +%Y%m%dT%H%M%SZ).json"
   lsof -iTCP -sTCP:LISTEN -P -n
   lsof -i -n -P | grep -v '127.0.0.1\|\[::1\]'
   ```
3. Read `python_egress_attempts_blocked` and the recorded violations. A blocked attempt is the control
   working — but an *unexplained* blocked attempt is still an incident: something in-process tried to reach
   the network.
4. Determine whether the caller was in-process Python (covered by L1/L2) or native/external code (**not**
   covered — `grpcio`'s C core, ONNX Runtime, `ctypes`, Ollama, Docker). If native, the Python counters are
   silent and you have no in-process evidence either way. Say that plainly in the report.
5. If pf is loaded: `sudo pfctl -a sagp -s info`.
6. Preserve `audit/`, `evidence/`, and the capture; then run `make verify` and attach the verdict.

### 7.2 Manifest mismatch

1. `make serve` refusing to boot on a mismatch is **correct behaviour**. Do not work around it.
2. `make verify-manifest` names the path and offset of the first mismatch.
3. Classify: a file **present but unmanifested** (something wrote into the artifact tree) · a file whose
   **interior bytes changed** (tampering or disk corruption) · a **missing** file (incomplete provision or
   deletion).
4. Do **not** regenerate `MANIFEST.json` to make the error go away — that destroys the only evidence.
5. Compare against the committed `models/MANIFEST.json` in git and against the last signed evidence report's
   `root_hash`.
6. If unexplained, treat as compromise: preserve, then re-provision from scratch through §6. Do not "repair"
   individual files.

### 7.3 Audit chain break

1. `make audit-verify` → `ChainReport(ok=False, first_bad_seq=N, reason=…)`. Record `N` and the reason.
2. Records before `N` remain verifiable against the last exported head digest; records from `N` onward are
   not trustworthy.
3. Compare the current head against your last off-box export ([Operations](OPERATIONS.md) §2). **Without
   that export the chain is only tamper-evident against an attacker who lacks write access** — an attacker
   with write access rebuilds the chain from any point and `make audit-verify` comes back green. If you have
   no export, say so; do not claim tamper-evidence you cannot substantiate.
4. Copy the affected JSONL files to read-only media before anything else.
5. Do not truncate or rewrite the ledger. Start a new file and record the break as its first event.

### 7.4 Suspected poisoned document

1. Identify the document by `doc_sha256` from its ingest audit record.
2. Inspect what the ingest guard already decided:
   ```bash
   # every /v1/admin/* route is gated on pii:reveal — use the REVEAL token, not $SAGP_API_TOKEN
   curl -s -H "Authorization: Bearer $SAGP_API_TOKEN_REVEAL" \
        http://127.0.0.1:8000/v1/admin/quarantine | python3 -m json.tool
   ```
   Chunks scoring ≥ 0.95, carrying a high-confidence heuristic, or flagged `truncated=True` are already in
   the `<collection>__quarantine` sibling and were never retrievable. Pages flagged `PDF_TINY_FONT`, `PDF_OFFPAGE_TEXT`, or
   `PDF_INVISIBLE_RENDER` were quarantined at load.
3. Remove the **whole document**, not just the offending chunk: delete by `doc_sha256` from the main
   collection.
4. Re-examine any recent answer that cited it — the retrieval-time re-scan of the assembled context
   (threshold 0.90, adjacent-window corroboration) is the layer that would have caught it late.
5. Add the payload to `tests/corpus/attacks.jsonl` with its technique tag, then `make eval`. A poisoned
   document that got through is a corpus gap, and the corpus is the only thing that stops it recurring.
6. Standing limitation: the classifier's own card states it **does not detect jailbreak attacks** and does
   not handle non-English prompts. Category B and category F are reported separately for exactly this reason.

### 7.5 INT8 parity regression

1. Symptom: `07_gates.py` fails on a re-provision, or `guardrails/injection/selftest.py` refuses to start
   the app at boot.
2. **The app refusing to start is the control working.** A silently drifted injection classifier is worse
   than none.
3. Re-run the gate; read the reported `|Δ P(INJECTION)|` and the label-flip count. **Zero label flips** is
   the hard part — a flip means a previously-blocked attack now scores safe, or vice versa.
4. Walk the ladder: INT8 → FP32 ONNX (kept on disk for exactly this) → drop the LLM to `llama3.2:1b` only
   if RSS demands it. On this host it did not: the FP32 session RSS is **0.30 GB measured** (ORT mmaps the
   weights), the same budget INT8 would have used, so FP32 ships alongside `llama3.2:3b`.
5. Verify the label index is still resolved from `config.json` `id2label` (`{"0": "SAFE", "1": "INJECTION"}`,
   matched **casefolded**) and not hardcoded. A hardcoded index 1 is the inverted-guardrail bug: it blocks
   benign traffic and allows attacks.
6. Never lower a threshold or a metric floor to make the gate pass.

### 7.6 OOM / swap thrash

1. Symptom: a 2–5 s stall at the head of every request, generation in the low single-digit tok/s range, rising `Swapouts`.
2. Confirm with `vm_stat | grep -E 'Pageouts|Swapouts|compressor'`, `ollama ps`, and `/readyz`.
3. Find the cause — it is nearly always one of: an `8b` tag is configured (9.28 GB projected — **it does not
   fit in any configuration**) · `PROFILE=demo` is on, adding Docker Desktop's VM (system total ~7.60 GB
   projected for the demo profile, vs 6.75 GB projected for embedded — no margin either way) ·
   `en_core_web_lg` instead of `md` (+0.60 GB (ESTIMATE)) · more than one uvicorn worker. (The FP32
   classifier is the *shipped* config, not an OOM cause — its session RSS is **0.30 GB measured**, the same
   as INT8 would have used.)
4. Remediate: return to `llama3.2:3b-instruct-q4_K_M`, `SAGP_QDRANT_MODE=embedded`, `en_core_web_md`,
   `--workers 1`; close other applications.
5. **Treat this as a security event, not a performance one.** The pages macOS evicts under pressure are the
   idle guardrail models — the classifier and the spaCy pipeline not currently executing. Controls that
   eventually return the right answer are still degraded controls.
6. Standing limitation: denial of service by resource exhaustion is largely unmitigated on 8 GB. One worker
   plus `anyio.CapacityLimiter(2)` is the whole defence.

---

## 8. Decommissioning

1. **Settle retention obligations first.** Before deleting anything, confirm the retention period for
   `audit/` and `evidence/` against the retention table in [Compliance](COMPLIANCE.md). Audit records and
   the evidence ledger routinely outlive the system that produced them. If they must be retained, copy them
   off, verify the copy (`make audit-verify` against it), and export the final head digest
   ([Operations](OPERATIONS.md) §2) **before** touching the originals.
2. **Export the final evidence report.** `make proof` once more, on the still-sealed system. A
   decommissioning with no closing report leaves an unexplained gap at the end of the ledger.
3. **Destroy vault-adjacent and PII-bearing data.** Under `ingest_mode=raw` the vector store holds real
   document text.

   | Path | Contents | Action |
   |---|---|---|
   | `data/qdrant/` | real chunk text + embeddings | delete |
   | `data/private/` | operator-supplied source documents | delete |
   | `audit/` quarantine store | offending text captured at block time | delete **after** retention is settled |
   | `.env`, `.env.sealed` | API tokens, audit HMAC key, PII pepper | delete |
   | `.airgap/keys/manifest_ed25519` | signing private key | delete |
   | `models/`, `vendor/`, `.venv*` | weights and wheels; no PII | delete |

4. **The honest statement about secure deletion.** On an APFS SSD, `rm` unlinks; it does not overwrite, and
   `srm`-style tools are unsupported or ineffective on flash. **The only deletion assurance this host offers
   is FileVault key destruction** — erase the volume so the key is discarded (`diskutil apfs deleteContainer`
   or Erase All Content and Settings). If the data needed masking, it needs volume erasure rather than `rm`.
   Do not claim file-level secure deletion; you cannot substantiate it.
5. **Keep the public key.** `.airgap/keys/manifest_ed25519.pub` is committed — retain it with the archived
   evidence or nobody can verify the reports you kept in step 1.
6. **Record the decommissioning:** date, final `seal_generation`, final ledger head digest, what was
   retained, what was destroyed, and by whom.

---

## 9. Command reference

Sizes are from BLUEPRINT §8. **Every duration is an `(ESTIMATE)`** — no provisioning run has been timed on
this host.

| Target | Phase | What it does | Downloads | Duration |
|---|---|---|---|---|
| `make doctor` | any | Read-only preflight: python, disk (hard-fail < 25 GB), RAM, docker, ollama | — | < 5 s |
| `make venvs` | BOOTSTRAP | Creates `.venv` + `.venv-provision` from `~/.local/bin/python3.11` | — | 30–60 s |
| `make lock` | BOOTSTRAP | Resolves both closures once; emits `requirements.*.lock` with `--generate-hashes` | metadata | 2–5 min |
| `make install` | BOOTSTRAP | `pip install --require-hashes -r requirements.runtime.lock -e .` | ~0.45 GB installed | 2–4 min |
| `make spike-docker` | BOOTSTRAP (Phase 0) | Resolved OQ-4 (`internal: true` breaks host reachability → non-internal bridge) and OQ-5 (`enable_ip_masquerade: "false"` does **not** block egress on Docker Desktop; DNS leaks via the embedded resolver) empirically → ADR-0002 **Accepted**. **RUN 2026-08-01** (§1); Docker path NOT isolated by compose options | ~10 MB | ~10 min |
| `make provision` | PROVISION | Steps 01–10; resumable; idempotent; **non-zero exit on any gate failure** | **~8.2 GB**, plus the 4.7 GB `llama3:8b` tag pulled at A4 — included in BLUEPRINT §8's totals | 25–55 min |
| `make verify-online` | PROVISION | Negative control: probes succeed in `audit` mode, raise `EgressViolation` in `enforce` | — | < 30 s |
| `make eval` | PROVISION | Corpus run → `docs/metrics/latest.json` (**created at M6; the file now exists and is committed**); >2pp regression fails the build | — | 3–10 min |
| `make seal` | PROVISION→OPERATE | Writes `.env.sealed` + `state.json`; installs the `.pth` guard; `seal_generation++` | — | < 10 s |
| `make seal-pf` | SEAL | Phase 2, immediately after `make seal` and **before** the physical disconnect (§3 B3). Loads `deploy/pf/com.sagp`. **Dry-run parse first.** `sudo` | — | < 10 s |
| `make ollama-up` | OPERATE | launchd plist, loopback-bound, env from `.env.sealed` | — | 5–20 s |
| `make up` | OPERATE | `PROFILE=demo` only: `docker load` + `compose up qdrant` | — | 20–60 s |
| `make serve` | OPERATE | `bin/sagp-serve` → uvicorn `--workers 1 --host 127.0.0.1`; full manifest verify at boot | — | 15–40 s |
| `make ingest FILE=… COLLECTION=…` | OPERATE | Ingest path I1–I11 through the same guardrails | — | 5–60 s/doc |
| `make query Q="…"` | OPERATE | One request through the chat path C0–C26 | — | 5–30 s |
| `make smoke` | OPERATE | 14 numbered PASS/FAIL checks (`--fast` uses `FakeLLM`) | — | 1–5 min |
| `make verify` | VERIFY | The 9 offline assertions + paired controls; non-zero exit on any failure | — | 10–30 s |
| `make verify-manifest` | any | Full manifest verify; names the first mismatching path | — | 2–5 s |
| `make evidence` | VERIFY | Signed `EVIDENCE-<gen>-<utc>.json`/`.md` + ledger append | — | < 10 s |
| `make audit-verify` | any | Hash-chain walk over `audit/*.jsonl`; exit 1 on any break | — | < 30 s |
| `make proof` | VERIFY | `verify` + `evidence` | — | < 60 s |
| `make unseal REASON="…"` | OPERATE→PROVISION | Appends to `unseal_history`; the only way back through the door | — | < 5 s |
| `make lint typecheck test` | any | Static checks + unit/integration suites | — | 2–10 min |
| `make test-e2e` | OPERATE | Golden path with real models and real Ollama | — | 5–15 min |

**See also:** [Architecture](ARCHITECTURE.md) · [Threat model](THREAT_MODEL.md) · [Guardrails](GUARDRAILS.md)
· [Operations](OPERATIONS.md) · [Compliance](COMPLIANCE.md) · [Limitations](LIMITATIONS.md) ·
[Blueprint](BLUEPRINT.md) · [Plan](PLAN.md) · [README](../README.md)
