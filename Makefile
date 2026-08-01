# sagp — the only supported entrypoint for every task.
# The repo path contains spaces, so every path is quoted everywhere.
.SHELLFLAGS := -eu -o pipefail -c
SHELL := /bin/bash
.DEFAULT_GOAL := help

PY311   := $(HOME)/.local/bin/python3.11
VENV    := .venv
VENV_PROVISION := .venv-provision
PIP     := "$(VENV)/bin/pip"
PYTHON  := "$(VENV)/bin/python"
PROV_PY := "$(VENV_PROVISION)/bin/python"
RUFF    := "$(VENV)/bin/ruff"
MYPY    := "$(VENV)/bin/mypy"
PYTEST  := "$(VENV)/bin/pytest"

.PHONY: help doctor venvs install install-provision lint format typecheck test test-ci test-all test-e2e clean \
        provision verify-manifest audit-verify eval eval-candidate production-preflight samples \
        audit-deps sbom \
        verify verify-online evidence proof smoke \
        seal unseal serve airgap-status spike-docker seal-pf unseal-pf \
        ingest query up ollama-up ollama-down

help:  ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

doctor:  ## Read-only preflight: Python 3.11, interpreter present
	@test -x "$(PY311)" || { echo "missing interpreter: $(PY311)"; exit 1; }
	@"$(PY311)" -c 'import sys; v=sys.version_info; assert (v.major,v.minor)==(3,11), f"need 3.11, got {v.major}.{v.minor}"; print(f"python {sys.version.split()[0]} OK at {sys.executable}")'

venvs:  ## Create .venv (sealed runtime) and .venv-provision (online only)
	@test -x "$(PY311)" || { echo "missing interpreter: $(PY311)"; exit 1; }
	"$(PY311)" -m venv "$(VENV)"
	"$(PY311)" -m venv "$(VENV_PROVISION)"
	$(PIP) install --quiet --upgrade pip
	@echo "created $(VENV) and $(VENV_PROVISION)"

install:  ## Install the runtime closure + [dev] into .venv (online)
	$(PIP) install --upgrade pip
	$(PIP) install -e '.[dev]'

install-provision:  ## Install the provisioning toolchain into .venv-provision (online)
	"$(VENV_PROVISION)/bin/pip" install --upgrade pip
	"$(VENV_PROVISION)/bin/pip" install -r requirements.provision.txt

lint:  ## ruff check + format --check
	$(RUFF) check src tests
	$(RUFF) format --check src tests

format:  ## ruff format (writes)
	$(RUFF) format src tests
	$(RUFF) check --fix src tests

typecheck:  ## mypy (strict) over src/sagp
	$(MYPY)

test:  ## Unit + integration suites (FakeLLM/FakeScorer, no models)
	$(PYTEST) -q

test-ci:  ## The model-free subset CI runs (no provisioned models / Ollama). Marker-selected.
	$(PYTEST) -m "not needs_models and not needs_ollama" -q

test-all:  ## Full suite incl. needs_models (real ONNX + spaCy) and needs_ollama (provisioned host)
	$(PYTEST) -q

test-e2e:  ## Golden path against real models + a live Ollama (the needs_ollama subset)
	$(PYTEST) -m "needs_ollama" -q

provision:  ## PROVISION EVERYTHING (online, one-way door): steps 01..10 in order
	@$(PYTHON) -m sagp.netguard.phase to-provision
	bash scripts/provision/01_wheelhouse.sh
	$(PROV_PY) scripts/provision/02_hf_models.py
	$(PYTHON) scripts/provision/03_spacy.py
	bash scripts/provision/04_ollama.sh
	bash scripts/provision/05_docker.sh
	$(PROV_PY) scripts/provision/06_quantize.py
	$(PROV_PY) scripts/provision/07_gates.py
	$(PYTHON) scripts/provision/08_tldextract.py
	$(PYTHON) scripts/provision/09_secrets.py
	$(PYTHON) scripts/provision/10_manifest.py
	@echo "provision complete — run 'make verify-manifest'"

eval-candidate:  ## Injection-classifier bake-off (online, provision venv): CANDIDATE=<repo> NAME=<slug>
	@test -n "$(CANDIDATE)" || { echo "usage: make eval-candidate CANDIDATE=<hf-repo-or-dir> NAME=<slug>"; exit 2; }
	@test -n "$(NAME)" || { echo "usage: make eval-candidate CANDIDATE=<hf-repo-or-dir> NAME=<slug>"; exit 2; }
	PYTHONPATH="$(PWD)/src" $(PROV_PY) scripts/eval_classifier_candidate.py --candidate "$(CANDIDATE)" --name "$(NAME)"

production-preflight:  ## Honest production go/no-go: automated gates + human checklist (exits nonzero until ready — by design)
	PYTHONPATH="$(PWD)/src" $(PYTHON) scripts/production_preflight.py

PIP_AUDIT ?= "$(VENV)/bin/pip-audit"
CYCLONEDX ?= "$(VENV)/bin/cyclonedx-py"
# Known-accepted advisories (id[,id...]) — none today; append with justification in the PR.
AUDIT_IGNORE ?=

audit-deps:  ## CVE-scan the installed environment (pip-audit). Fails on a known vulnerability.
	$(PIP_AUDIT) $(foreach v,$(AUDIT_IGNORE),--ignore-vuln $(v))

sbom:  ## Generate a RUNTIME-ONLY CycloneDX SBOM -> sbom.cdx.json (clean venv, no dev/test tools)
	rm -rf .sbom-venv
	"$(PY311)" -m venv .sbom-venv
	.sbom-venv/bin/pip install --quiet --upgrade pip "setuptools>=83.0.0"
	.sbom-venv/bin/pip install --quiet -e .
	$(CYCLONEDX) environment .sbom-venv --output-format JSON > sbom.cdx.json
	rm -rf .sbom-venv
	@echo "wrote sbom.cdx.json ($$( $(PYTHON) -c 'import json;print(len(json.load(open("sbom.cdx.json"))["components"]))' ) components, runtime-only)"

verify-manifest:  ## Full manifest verification (recompute every hash + signature)
	$(PYTHON) -m sagp.netguard.manifest

samples:  ## Generate the synthetic sample PDFs into data/samples/
	$(PYTHON) scripts/gen_sample_pdf.py

eval:  ## Corpus metrics -> docs/metrics/latest.json (real models; commit the result)
	$(PYTHON) scripts/eval_guardrails.py

audit-verify:  ## Walk the audit hash chain; exit 1 on any break
	$(PYTHON) -m sagp.audit.verify

verify:  ## OFFLINE proof: the 9 air-gap assertions + invariant-13 verdict
	$(PYTHON) scripts/verify_airgap.py

verify-online:  ## NEGATIVE CONTROL (run during PROVISION, internet UP): audit vs enforce
	$(PYTHON) scripts/verify_online.py

evidence:  ## Sign the EVIDENCE-<gen>-<utc> report + append the hash-chained ledger
	$(PYTHON) scripts/evidence.py

proof:  ## verify + evidence
	$(MAKE) verify
	$(MAKE) evidence

smoke:  ## 14 numbered functional checks (guard armed, FakeLLM)
	bash scripts/smoke.sh

seal:  ## ONE-WAY DOOR: write .env.sealed, install .pth guard, PROVISION -> OPERATE (gated)
	bash scripts/seal.sh

unseal:  ## OPERATE -> PROVISION, one controlled reconnection. Requires REASON="…"
	$(PYTHON) scripts/unseal.py "$(REASON)"

serve:  ## The only supported launch path: bin/sagp-serve -> uvicorn --workers 1 (loopback)
	bash bin/sagp-serve

airgap-status:  ## Print phase, seal_generation, unseal count
	$(PYTHON) -m sagp.netguard.phase status

spike-docker:  ## Online, Docker running: resolve OQ-4/OQ-5 empirically -> ADR-0002
	bash scripts/spike_docker.sh

bench:  ## Measure app-process RSS + per-request latency (single-host, idle; not a load test)
	$(PYTHON) scripts/bench.py

bench-load:  ## Measure the HTTP path under concurrency (burst; live uvicorn)
	$(PYTHON) scripts/bench_load.py

seal-pf:  ## OPTIONAL, sudo, HOST-WIDE: pf blocks all non-loopback egress (dry-run parsed first)
	bash scripts/seal_pf.sh

unseal-pf:  ## Reverse make seal-pf: restore /etc/pf.conf backup, flush the com.sagp anchor
	bash scripts/unseal_pf.sh

ingest:  ## Ingest a local PDF through the guardrails: make ingest FILE=… COLLECTION=…
	$(PYTHON) scripts/ingest.py "$(FILE)" "$(COLLECTION)"

query:  ## One guarded chat request: make query Q="…" [COLLECTION=…]
	$(PYTHON) scripts/query.py "$(Q)" "$(COLLECTION)"

up:  ## PROFILE=demo only: docker load (if saved) + compose up qdrant (loopback)
	@[ -f models/docker/qdrant.tar ] && docker load -i models/docker/qdrant.tar || echo "up: no saved image at models/docker/qdrant.tar (pulled at provision); relying on local cache"
	docker compose up -d qdrant

ollama-up:  ## Install + load the ai.sagp.ollama launchd agent (loopback ollama serve)
	bash scripts/ollama_up.sh

ollama-down:  ## Unload the ai.sagp.ollama launchd agent
	launchctl unload "$(HOME)/Library/LaunchAgents/ai.sagp.ollama.plist" 2>/dev/null || true
	@echo "ollama-down: unloaded ai.sagp.ollama (if it was loaded)"

clean:  ## Remove venvs and caches
	rm -rf "$(VENV)" "$(VENV_PROVISION)" .pytest_cache .ruff_cache .mypy_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
