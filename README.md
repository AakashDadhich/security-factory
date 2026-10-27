# Security Software Factory

A pipeline on GitHub Actions that takes an app (iOS, macOS or web) from spec to code and checks it at every step: threat modelling, secure code generation, static analysis, dependency and secret scanning, dynamic testing and a release gate. The orchestrator is plain Python; AI runs only inside specific stages.

The build plan, split into chunks with their dependencies, starts at [plan/00-index.md](plan/00-index.md).

Run the factory's own tests with `make test`.
