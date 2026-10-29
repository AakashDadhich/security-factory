.PHONY: help test tools-list ensure-make secrets sast-semgrep semgrep-test sast-eslint deps-sbom dast-up dast-web dast-down rules plan threat-model

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
	@echo "make dast-web     Run the ZAP full scan (OpenAPI import and active scan) against the running app"
	@echo "make dast-down    Remove the DAST containers and network"
	@echo "make plan        Run the plan stage on ISSUE_FILE (JSON with title and body)"
	@echo "make threat-model Build the pytm model and STRIDE threats from PLAN_FILE"
	@echo "make rules       Render CLAUDE.md and AGENTS.md for PLATFORM and ASVS_LEVEL (default 2) into out/rules"

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
	python -m factory.stages.dast_web --out out/dast-web

dast-down:
	python -m factory.dast.harness down

ASVS_LEVEL ?= 2

rules:
	python -m factory.rules render --platform $(PLATFORM) --asvs-level $(ASVS_LEVEL) --target claude --out out/rules/CLAUDE.md
	python -m factory.rules render --platform $(PLATFORM) --asvs-level $(ASVS_LEVEL) --target agents --out out/rules/AGENTS.md

ISSUE_FILE ?= out/plan/issue.json

plan:
	python -m factory.stages.plan --issue-file $(ISSUE_FILE) --config .factory.yml --out out/plan

PLAN_FILE ?= out/plan/plan.json

threat-model:
	python -m factory.stages.threat_model --plan $(PLAN_FILE) --previous security --out out/threat-model
