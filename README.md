# Security Software Factory

[![selftest](https://github.com/AakashDadhich/security-factory/actions/workflows/selftest.yml/badge.svg?branch=main)](https://github.com/AakashDadhich/security-factory/actions/workflows/selftest.yml)
[![acceptance](https://github.com/AakashDadhich/security-factory/actions/workflows/acceptance.yml/badge.svg?branch=main)](https://github.com/AakashDadhich/security-factory/actions/workflows/acceptance.yml)

A pipeline on GitHub Actions that takes an app (iOS, macOS or web) from spec to code and checks it at every step: threat modelling, secure code generation, static analysis, dependency and secret scanning, dynamic testing and a fail-closed release gate. The orchestrator is plain Python; AI runs only inside specific stages, always through one model adapter.

One public repository serves every project. A project adds a small stub workflow that calls the factory at `@v1`, and a `.factory.yml`. Start with [docs/onboarding.md](docs/onboarding.md) or the template repository [factory-project-template](https://github.com/AakashDadhich/factory-project-template).

## Portfolio documentation

- [Case study](docs/portfolio/case-study.md): problem, approach, results from the acceptance tests, cost
- [Diagrams](docs/portfolio/diagrams.md): end-to-end flow, CI layout, model adapter, job graphs per mode
- [Stages](docs/portfolio/stages.md): purpose, tool, input, output and gate behaviour for each stage
- [Securing the factory](docs/portfolio/factory-security.md): how the pipeline protects itself
- [OWASP SAMM self-assessment](docs/portfolio/samm.md)
- [Limits](docs/portfolio/limits.md): the honest gaps

## Reference

- [Pipeline](docs/pipeline.md), [model adapter](docs/adapter.md), [data contracts](docs/contracts.md), [project record](docs/record.md), [acceptance tests](docs/acceptance.md), [releasing](docs/release.md), [runners](docs/runners.md)
- Tool and design decisions: [plan/decisions.md](plan/decisions.md)
- The build plan, split into chunks, starts at [plan/00-index.md](plan/00-index.md)

Run the factory's own tests with `make test`.
