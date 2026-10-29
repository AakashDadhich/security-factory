.PHONY: help test tools-list ensure-make secrets sast-semgrep semgrep-test sast-eslint deps-sbom dast-up dast-web dast-down

help:
	@echo "make test         Run the factory test suite"
	@echo "make tools-list   List pinned tools in tools/versions.lock"
	@echo "make ensure-make  Check make is available (installs it on macOS if missing)"
	@echo "make secrets      Scan git history for secrets and committed .env files"
	@echo "make sast-semgrep Run Semgrep on PLATFORM (default web) over SRC (default .)"
	@echo "make semgrep-test Run the custom Semgrep rule tests"
	@echo "make sast-eslint  Run the factory ESLint security config over SRC (default .)"
	@echo "make deps-sbom    Scan dependencies and write a CycloneDX SBOM for SRC (default .)"
	@echo "make dast-up      Build and start the throwaway app on the isolated DAST network"
	@echo "make dast-web     Run the ZAP baseline scan against the running app"
	@echo "make dast-down    Remove the DAST containers and network"

test:
	python -m pytest -v

tools-list:
	python -m factory.tools list

ensure-make:
	python -m factory.platform_check ensure-make

secrets:
	python -m factory.stages.secrets --repo . --out out/secrets

PLATFORM ?= web
SRC ?= .

sast-semgrep:
	python -m factory.stages.sast_semgrep --platform $(PLATFORM) --src $(SRC) --out out/sast-semgrep

semgrep-test:
	semgrep --test --metrics=off --disable-version-check semgrep-rules/custom

sast-eslint:
	python -m factory.stages.sast_eslint --src $(SRC) --out out/sast-eslint

deps-sbom:
	python -m factory.stages.deps_sbom --src $(SRC) --out out/deps-sbom

dast-up:
	python -m factory.dast.harness up

dast-web:
	python -m factory.stages.dast_web --plan baseline --out out/dast-web

dast-down:
	python -m factory.dast.harness down
