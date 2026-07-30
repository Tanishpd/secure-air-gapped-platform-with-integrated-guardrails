# Third-party licences

Every pinned runtime dependency, provisioning dependency, model artefact, and container image used by
`sagp`, with its SPDX identifier and the location of its licence text. Package versions and model
revisions are taken from [docs/BLUEPRINT.md §2](docs/BLUEPRINT.md) and must stay identical to
`requirements.runtime.lock`, `requirements.provision.lock`, and `artifacts.lock`.

---

## 0. Read this first

**No model weights are redistributed by this repository.** Nothing under `models/` is committed —
`.gitignore` excludes `models/**` with two deliberate exceptions, `models/MANIFEST.json` and
`models/README.md`, neither of which contains any part of a model. Every weight file is fetched from
its upstream publisher during Phase 1 (PROVISION) by pinned commit SHA or image digest, and is then
recorded by sha256 in `MANIFEST.json`. This repository distributes an **inventory and a verification
procedure**, not artefacts. Your obligations under each model licence attach when *you* download the
model, and they are yours.

**Licence identifiers below are UNVERIFIED on this machine.** Phase 1 has not been run — there is no
`vendor/wheelhouse/`, no `models/`, and no installed distribution metadata to read (free disk is
5.9 GB against a 25 GB requirement). Every SPDX identifier in this file was recorded from package
metadata known at authoring time and **must be re-verified against the actual wheel `METADATA` and
`dist-info` licence files during provisioning, before the first release.** Treat this document as a
checklist to confirm, not as a finding.

Extraction command for that verification pass (there is no `make licenses` target in the blueprint's
Makefile — adding one is a **proposed** change, not an existing capability; as of 2026-07-27 no `Makefile`
exists at all, the repository being documentation only):

```bash
ROOT="/Users/tanishpd/Desktop/Secure Air-Gapped Platform with Integrated Guardrails"
"$ROOT/.venv/bin/python" - <<'PY'
from importlib.metadata import distributions
for d in sorted(distributions(), key=lambda x: x.metadata["Name"].lower()):
    m = d.metadata
    print(m["Name"], m["Version"],
          m.get("License-Expression") or m.get("License") or "UNDECLARED",
          [f.name for f in (d.files or []) if "LICEN" in f.name.upper()], sep=" | ")
PY
```

**A known gap in the current provisioning plan.** `scripts/provision/02_hf_models.py` calls
`snapshot_download(...)` with `allow_patterns` covering only config, ONNX, and tokenizer files
([BLUEPRINT.md §2.3](docs/BLUEPRINT.md)). **Those patterns do not include the models' `LICENSE` or
`README.md` files, so the model licence texts will not be present on the sealed host.** For a
compliance-themed template that is the wrong default. Add `LICENSE*`, `NOTICE*`, and `README.md` to the
`allow_patterns` for both model repositories, include them in `MANIFEST.json`, and check that the
downloaded text matches what this table claims. Until that change lands, the "where the licence text
lives" column for HuggingFace models describes an intended location, not an existing file.

---

## 1. Runtime dependencies — `.venv` (the sealed runtime)

Direct and explicitly-pinned dependencies from [BLUEPRINT.md §2.1](docs/BLUEPRINT.md).

| Component | Version | SPDX identifier | Where the licence text lives |
|---|---|---|---|
| CPython | 3.11.15 | `PSF-2.0` | `~/.local/bin/../lib/python3.11/LICENSE.txt`; also `python3.11 -c "import sys; print(sys.copyright)"` |
| fastapi | 0.140.1 | `MIT` | `vendor/wheelhouse/fastapi-0.140.1-*.whl` → `fastapi-0.140.1.dist-info/` licence file |
| uvicorn[standard] | 0.51.0 | `BSD-3-Clause` | `vendor/wheelhouse/uvicorn-0.51.0-*.whl` → dist-info licence file |
| pydantic | 2.13.4 | `MIT` | dist-info licence file |
| pydantic-settings | 2.14.2 | `MIT` | dist-info licence file |
| python-multipart | 0.0.32 | `Apache-2.0` | dist-info licence file |
| presidio-analyzer | 2.2.364 | `MIT` | dist-info licence file; source at `github.com/data-privacy-stack/presidio` tag `2.2.364` (the repo moved from `github.com/microsoft/presidio` — see BLUEPRINT.md §1.2) |
| presidio-anonymizer | 2.2.364 | `MIT` | as above |
| spacy | 3.8.13 | `MIT` | dist-info licence file; wheel `spacy-3.8.13-cp311-cp311-macosx_11_0_arm64.whl` (6,441,498 B) |
| thinc-apple-ops | 1.0.0 | `MIT` | dist-info licence file (installed via the `spacy[apple]` extra) |
| onnxruntime | 1.28.0 | `MIT` | dist-info licence file; wheel `onnxruntime-1.28.0-cp311-cp311-macosx_14_0_arm64.whl` (19,130,506 B) |
| tokenizers | 0.23.1 | `Apache-2.0` | dist-info licence file |
| numpy | >=1.26,<2.5.0 | `BSD-3-Clause` | dist-info licence file (ceiling imposed by presidio's `numpy<2.5.0,>=1.19.0`) |
| qdrant-client | 1.18.0 | `Apache-2.0` | dist-info licence file |
| ollama (Python client) | 0.6.2 | `MIT` | dist-info licence file |
| pypdf | 6.14.2 | `BSD-3-Clause` | dist-info licence file — **see §5, the PyMuPDF rejection** |
| pyyaml | >=6.0.3,<7 | `MIT` | dist-info licence file |
| regex | >=2024.11 | `Apache-2.0 AND CNRI-Python` | Current releases declare License-Expression `Apache-2.0 AND CNRI-Python` (the CNRI-derived component was always present in the licence file; releases before ~2025 declared only "Apache Software License" in metadata). **Confirm against the resolved version's metadata and pin it.** |
| phonenumbers | 9.0.35 | `Apache-2.0` | dist-info licence file (Python port of libphonenumber) |
| tldextract | 5.3.1 | `BSD-3-Clause` | dist-info licence file. Note the bundled Public Suffix List snapshot, §1.1 below. |
| cryptography | >=48.0.1,<49 | `Apache-2.0 OR BSD-3-Clause` | dist-info; the distribution ships both texts. Pulled transitively by presidio-anonymizer. Statically links OpenSSL — see §1.1. |
| grpcio | 1.71.0 | `Apache-2.0` | dist-info licence file. **OPEN QUESTION — OQ-7:** the exact resolved version is unverified; `qdrant-client==1.18.0` requires `grpcio>=1.41.0` with no upper bound. Pin whatever the resolver produces into `requirements.runtime.lock` and update this row. Ships a NOTICE file that must be reproduced — see [NOTICE](NOTICE). |
| protobuf | >=4.25.8,<6 | `BSD-3-Clause` | dist-info licence file |
| httpx | 0.28.1 | `BSD-3-Clause` | dist-info licence file |

### 1.1 Bundled data and statically-linked components inside those wheels

These are not separate PyPI entries but carry their own terms and must appear in any distribution review.

| Bundled component | Inside | SPDX identifier | Notes |
|---|---|---|---|
| Public Suffix List snapshot | `tldextract` 5.3.1, and the warmed cache at `models/tldextract/` | `MPL-2.0` | The PSL is published by Mozilla under MPL-2.0. `scripts/provision/08_tldextract_cache.py` warms this snapshot to disk so `SealedEmailRecognizer` never fetches it over HTTPS. Because the snapshot is written into `models/` and hashed into `MANIFEST.json`, it is a redistributed data file on any machine that copies the provisioned tree. |
| OpenSSL | `cryptography` wheels | `Apache-2.0` | The manylinux/macOS wheels statically link OpenSSL 3.x, which is Apache-2.0 licensed. |
| ONNX Runtime native libraries and their dependencies | `onnxruntime` 1.28.0 | `MIT` plus third-party components | The wheel embeds several third-party libraries with their own notices. Read `onnxruntime/ThirdPartyNotices.txt` inside the installed package during the verification pass and append anything required to [NOTICE](NOTICE). |
| libphonenumber metadata | `phonenumbers` 9.0.35 | `Apache-2.0` | Google's metadata tables, redistributed by the Python port. |

The full transitive closure — `starlette`, `anyio`, `httpcore`, `h11`, `certifi` (`MPL-2.0`), `idna`,
`urllib3`, `requests`, `requests-file`, `filelock`, `portalocker`, `click`, `typing-extensions`, the
`thinc`/`cymem`/`preshed`/`murmurhash`/`srsly`/`catalogue`/`wasabi` spaCy stack, and the rest — is
defined by `requirements.runtime.lock` and is **not** enumerated by hand here. Generate it with the
command in §0 and attach the output to the release. Enumerating it manually would guarantee it goes stale.

---

## 2. Provisioning dependencies — `.venv-provision` (online only)

These never sit on the sealed critical path. `.venv-provision` is deleted or left inert after
`make seal`. They still appear here because they are fetched, executed, and used to produce derived
artefacts that *do* ship to the sealed host.

| Component | Version | SPDX identifier | Where the licence text lives |
|---|---|---|---|
| huggingface-hub | 0.35.3 | `Apache-2.0` | `vendor/wheelhouse-provision/` → dist-info licence file |
| transformers | 4.57.6 | `Apache-2.0` | dist-info licence file; ships a NOTICE |
| torch | 2.9.1 | `BSD-3-Clause` | dist-info; the distribution ships `LICENSE` and a large `NOTICE`/third-party notices file covering bundled components. Used only for tokenizer and FP32↔INT8 parity checks. |
| onnx | 1.22.0 | `Apache-2.0` | dist-info licence file |
| onnxruntime[quantization] | 1.28.0 | `MIT` | as §1; the `quantization` extra pulls `ml_dtypes` (`Apache-2.0`) |
| sentence-transformers | 5.6.1 | `Apache-2.0` | dist-info licence file. Used **only** to produce the embedding parity fixture in `scripts/provision/07_gates.py`. |
| pytest | 9.1.1 | `MIT` | dist-info licence file |

---

## 3. Model artefacts

**None of these are redistributed by this repository.** Each is fetched from its publisher during
Phase 1 at the exact revision below, and recorded by per-file sha256 in `MANIFEST.json`.

| Artefact | Version / revision | SPDX identifier | Where the licence text lives |
|---|---|---|---|
| `protectai/deberta-v3-base-prompt-injection-v2` (prompt-injection classifier) | commit `90c9989b1a342275dd0d1a95aad283c04e075671` | `Apache-2.0` | Model card and `LICENSE` in the HuggingFace repo at that revision → intended local path `models/hf/injection/LICENSE` once the `allow_patterns` gap in §0 is fixed. |
| `BAAI/bge-small-en-v1.5` (embedder) | commit `5c38ec7c405ec4b44b94cc5a9bb96e735b38267a` | `MIT` | Model card and `LICENSE` in the HuggingFace repo at that revision → intended local path `models/hf/bge/LICENSE`, same caveat. |
| `en_core_web_md` | 3.8.0 | `MIT` | Inside the wheel at `models/spacy/en_core_web_md-3.8.0-py3-none-any.whl` (33,480,380 B) → `en_core_web_md-3.8.0.dist-info/` and the pipeline's own `meta.json`, which carries a `license` field. |
| `en_core_web_sm` | 3.8.0 | `MIT` | `models/spacy/en_core_web_sm-3.8.0-py3-none-any.whl` (12,806,118 B), as above. Tests and low-memory profile. |
| `en_core_web_lg` | 3.8.0 | `MIT` | `models/spacy/en_core_web_lg-3.8.0-py3-none-any.whl` (400,658,291 B), as above. Opt-in only. |
| Ollama `llama3.2:3b-instruct-q4_K_M` (default LLM) | Ollama tag as pinned in `artifacts.lock`; 2.0 GB | **`LicenseRef-Llama-3.2-Community`** — see §3.1 | Embedded in the model blob under `models/ollama/`. Print with `OLLAMA_MODELS="$PWD/models/ollama" ollama show --license llama3.2:3b-instruct-q4_K_M` (UNVERIFIED that this prints the full text on Ollama client 0.30.10 — confirm during provisioning and save the output to `models/ollama/LICENSE-llama3.2.txt`). |
| Ollama `llama3.2:1b` (fallback) | 1.3 GB | **`LicenseRef-Llama-3.2-Community`** | as above |
| Ollama `llama3:8b` (**is provisioned; does not fit** — see BLUEPRINT.md §7) | 4.7 GB | **`LicenseRef-Llama-3-Community`** — a *different* licence from Llama 3.2 | as above, `ollama show --license llama3:8b`. It **is** pulled during step A4 — [PLAN.md §1](docs/PLAN.md) records that as an explicit operator choice, so the tag is one env var away — and pulling it is what creates the licence obligation recorded here. It is **not** a supported configuration on this 8 GB host: 9.28 GB projected for the embedded profile, worse under `PROFILE=demo`, both projections rather than measurements. |

### 3.1 Llama Community Licences — read this before deploying

The Llama 3.2 Community Licence (and, separately, the Meta Llama 3 Community Licence for the `llama3:8b`
tag) is **not an OSI-approved open-source licence.** It is a source-available community licence with
conditions that a compliance review must address:

- **It is not OSI-approved and is not "open source."** Do not describe a deployment of this template as
  running an open-source model without qualification.
- **An Acceptable Use Policy is incorporated by reference** and forms part of the licence. It prohibits
  categories of use. Read it against your actual use case — a regulated-enclave RAG deployment is not
  automatically inside it.
- **The 700-million-MAU condition.** If, on the licence's effective date, the licensee's products or
  services have more than 700 million monthly active users, a separate licence must be requested from
  Meta and Meta may grant or refuse it at its discretion.
- **Attribution and naming conditions apply** to redistribution and to derivative models, including
  displaying "Built with Llama" and naming requirements for derivatives.
- **Redistribution obligations.** If you redistribute the model or a derivative, you must supply a copy of
  the licence agreement.

Neither this document nor [docs/COMPLIANCE.md](docs/COMPLIANCE.md) is legal advice. Have counsel review
the licence text — printed from `ollama show --license` — against your intended use before deploying.
Swapping to a differently-licensed local model is a one-env-var change and is the correct answer if the
review comes back unfavourable.

---

## 4. Container images (`PROFILE=demo` and `PROFILE=proof` only)

Pinned by digest at provision and stored locally with `docker save`. Not used by the default profile,
which runs Qdrant embedded in-process.

| Image | Version | SPDX identifier | Where the licence text lives |
|---|---|---|---|
| `qdrant/qdrant` | `v1.18.3-unprivileged`, pinned by digest; ~70 MB compressed, ~0.15 GB as a tar | `Apache-2.0` | Qdrant source at `github.com/qdrant/qdrant`; the licence is also present inside the image filesystem. Note this covers the Qdrant server, which is a distinct artefact from the `qdrant-client` Python package in §1 (also `Apache-2.0`). |
| `alpine` | `3`, pinned by digest; ~4 MB compressed (~8 MB uncompressed) | **Multiple — not a single identifier** | An Alpine base image is a collection of packages under many licences. Two that matter for redistribution: `musl` (`MIT`) and `busybox` (**`GPL-2.0-only`**). If you redistribute the saved image tar, GPL source-availability obligations attach to the busybox component. Enumerate with `docker run --rm alpine:3 sh -c 'apk info -L --license 2>/dev/null || apk info'` and record the result. Used only as the egress prober in `PROFILE=proof`. |

---

## 5. Rejected: PyMuPDF, and why

> **PyMuPDF was rejected on licensing grounds and must not be added to this project.**

PyMuPDF is distributed under **AGPL-3.0** (with a paid commercial licence as the alternative).
**AGPL-3.0 §13 extends the copyleft obligation to network interaction**: if users interact with a
modified version of the program remotely through a computer network, they must be offered the
Corresponding Source of that version. `sagp` is a template for building an HTTP service. A service built
from this template, with PyMuPDF in its dependency graph, would inherit a network-copyleft obligation
covering the service's own source — an obligation that most organisations adopting an internal
compliance-themed enclave neither expect nor intend, and one that would be discovered late.

The decision is recorded in [BLUEPRINT.md §2.1](docs/BLUEPRINT.md) — the `pypdf` line, which names the
AGPL rejection directly — and in [BLUEPRINT.md §1.2](docs/BLUEPRINT.md). It is **not** a §0 decision row;
§0 row 11 is the unrelated `ingest_mode=raw` decision. See also [PLAN.md §2](docs/PLAN.md). **`pypdf==6.14.2` (`BSD-3-Clause`) is used instead**, and it is a real
constraint on the design rather than a free substitution: the hidden-text detection in
`src/sagp/rag/loaders.py` cannot compare extracted text against *rendered* text, because there is no
rasteriser. It uses pypdf's `visitor_text=(text, cm, tm, font_dict, font_size)` callback instead —
flagging near-zero font sizes, text placed outside the MediaBox via the text matrix, and
render-mode-3 fills. That is a weaker detector than rasterised comparison, and the weakness is
attributable to this licensing decision. It is documented in [docs/GUARDRAILS.md](docs/GUARDRAILS.md)
rather than hidden.

If you need rasterisation, obtain a commercial PyMuPDF licence or use a differently-licensed rasteriser —
do not add the AGPL package and hope.

---

## 6. This repository's own licence

The `sagp` source code is licensed under the **Apache License, Version 2.0** (SPDX: `Apache-2.0`). The
full, unmodified licence text is at [LICENSE](LICENSE) in the repository root; the attribution and
third-party notices required by its §4(d) are in [NOTICE](NOTICE), which must be reproduced alongside the
licence in any redistribution. That licence covers the code in this repository only. It does not, and
cannot, extend to:

- model weights (§3) — not redistributed here, each under its own terms, `llama3.2` notably not
  OSI-approved;
- container images (§4);
- any document an operator places in `data/private/`;
- any artefact fetched during provisioning.

`data/samples/*.pdf` will be generated by `scripts/gen_sample_pdf.py` at build time and must contain
**synthetic data only** — no real personal data, ever. `tests/corpus/*.jsonl` provenance and per-item
licensing are to be recorded in `tests/corpus/README.md`. Neither the script nor the corpus exists yet.

---

## 7. Maintaining this file

[CLAUDE.md](CLAUDE.md) §6, "Where things live": never change a pinned version, model ID, or revision
without updating `artifacts.lock`, `requirements.*.lock`, `MANIFEST.json`, and an ADR **in the same
change**. (That rule is a §6 table row, not one of the 13 numbered invariants in CLAUDE.md §2 — the
canonical invariant 7 is "never mask before scanning".) Add this file to that list — a version bump that
does not update the row here is an incomplete change.

Before any release, run the extraction command in §0 against a fully provisioned `.venv`, diff the output
against §1 and §2, resolve every `UNDECLARED`, and replace this section's UNVERIFIED status with a dated
statement of what was checked and how.
