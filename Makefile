.PHONY: help test

help:
	@echo "make test   Run the factory test suite"

test:
	python -m pytest -q
