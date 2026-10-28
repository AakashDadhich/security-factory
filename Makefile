.PHONY: help test tools-list ensure-make secrets sast-semgrep semgrep-test

help:
	@echo "make test         Run the factory test suite"
	@echo "make tools-list   List pinned tools in tools/versions.lock"
	@echo "make ensure-make  Check make is available (installs it on macOS if missing)"
	@echo "make secrets      Scan git history for secrets and committed .env files"
	@echo "make sast-semgrep Run Semgrep on PLATFORM (default web) over SRC (default .)"
	@echo "make semgrep-test Run the custom Semgrep rule tests"

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
