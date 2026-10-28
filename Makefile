.PHONY: help test tools-list ensure-make secrets

help:
	@echo "make test         Run the factory test suite"
	@echo "make tools-list   List pinned tools in tools/versions.lock"
	@echo "make ensure-make  Check make is available (installs it on macOS if missing)"
	@echo "make secrets      Scan git history for secrets and committed .env files"

test:
	python -m pytest -v

tools-list:
	python -m factory.tools list

ensure-make:
	python -m factory.platform_check ensure-make

secrets:
	python -m factory.stages.secrets --repo . --out out/secrets
