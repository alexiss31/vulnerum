# Vulnerum task runner.
# All targets run through `uv`; see README.md "Testing & CI" for the pipeline map.

UV ?= uv
PYTEST_FLAGS ?=

.PHONY: help setup fmt lint typecheck unit smoke sigma audit ci demo clean

help: ## Show available targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

setup: ## Sync the dev toolchain and install git hooks
	$(UV) sync --extra dev
	$(UV) run pre-commit install

fmt: ## Auto-format with ruff
	$(UV) run ruff format src tests
	$(UV) run ruff check --fix src tests

lint: ## Ruff lint + format check
	$(UV) run ruff check src tests
	$(UV) run ruff format --check src tests

typecheck: ## mypy strict over src and tests
	$(UV) run mypy src tests

unit: ## Unit tests (no Docker required)
	$(UV) run pytest -m "not docker" $(PYTEST_FLAGS)

smoke: ## Docker end-to-end lifecycle smoke tests (skips when Docker is unavailable)
	$(UV) run pytest -m docker $(PYTEST_FLAGS)

sigma: ## Validate Sigma rules with current SigmaHQ tooling
	$(UV) run pytest tests/test_sigma_rules.py $(PYTEST_FLAGS)
	uvx --from sigma-cli --with pysigma-backend-splunk sigma convert --without-pipeline -t splunk detection/sigma/ >/dev/null

# Task target `audit` passes `--ignore-vuln PYSEC-2026-2447` (diskcache, pulled in by
# the dev-only pySigma dependency): no fixed release exists upstream (all versions
# through 5.6.3 are affected) and diskcache is not part of the shipped runtime
# dependency set. Revisit when a fixed diskcache release lands.
audit: ## Bandit security lint + pip-audit dependency audit
	$(UV) run bandit -r src -c pyproject.toml
	$(UV) run pip-audit --ignore-vuln PYSEC-2026-2447

ci: lint typecheck unit sigma audit ## Full local CI gate (everything except Docker smoke)

demo: ## Run the full lifecycle for both labs (requires Docker)
	$(UV) run custos lab up cve-2021-41773
	$(UV) run custos verify cve-2021-41773
	$(UV) run custos run cve-2021-41773
	$(UV) run custos detect cve-2021-41773
	$(UV) run custos lab up cve-2021-41773 --mitigated
	$(UV) run custos run cve-2021-41773 --retest
	$(UV) run custos lab up cve-2021-44228
	$(UV) run custos verify cve-2021-44228
	$(UV) run custos run cve-2021-44228
	$(UV) run custos detect cve-2021-44228
	$(UV) run custos lab up cve-2021-44228 --mitigated
	$(UV) run custos run cve-2021-44228 --retest
	$(UV) run custos report cve-2021-41773
	$(UV) run custos report cve-2021-44228

clean: ## Remove generated artifacts and caches
	rm -rf artifacts .pytest_cache .mypy_cache .ruff_cache dist build src/*.egg-info
