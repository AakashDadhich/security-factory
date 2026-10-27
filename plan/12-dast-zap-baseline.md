# 12. DAST: container harness and ZAP baseline

## Goal
For web projects: build the app into a container, start it as a throwaway instance on an isolated Docker network, and run a passive OWASP ZAP baseline scan against it, producing findings.

## Inputs
- `plan/PROGRESS.md`
- From chunk 02: the installer (`container` kind)
- From chunk 06: `factory.yml`, and `factory/config.py` (gives `web.port`, `web.health_path`, `web.dockerfile`)
- Project `factory-test-web` with its `Dockerfile`

## Tasks
1. Add a lock entry `zap` (`kind = "container"`, `ghcr.io/zaproxy/zaproxy` stable, pinned by `@sha256:` digest).
2. Write `factory/dast/harness.py`, run as `python -m factory.dast.harness up|down --config .factory.yml`:
   - Create the network with `docker network create --internal factory-dast`, so neither container can reach the internet.
   - Build the image with `docker build -t factory-app:<run_id>`, then run it detached on that network with the alias `app`, with `--read-only`, a tmpfs for `/tmp`, `--cap-drop ALL` and `--security-opt no-new-privileges`. Pass env vars only from `.env.example` (fake values).
   - Wait for `http://app:<port><health_path>` to return 200, polling from a throwaway `curlimages/curl` container on the same network (also pinned by digest), with a 120 second timeout. On timeout, dump the container logs and fail.
   - `down` removes the containers and the network.
3. Write `zap/baseline.yaml`, a ZAP Automation Framework plan: an `env` context for `http://app:<port>`, then `spider` (bounded, max 2 minutes), `passiveScan-wait`, and a `report` step in JSON (`traditional-json`) and HTML. Template the target URL from config.
4. Write `factory/stages/dast_web.py`, run as `python -m factory.stages.dast_web --plan baseline --out out/dast-web`. It runs the pinned ZAP image on the same network with `zap.sh -cmd -autorun /zap/wrk/<plan>.yaml`, the plan mounted into `/zap/wrk`, and then converts the JSON report to findings: riskcode 3 = high, 2 = medium, 1 = low, 0 = info. Location is `{url, method}`, CWE comes from `cweid`, and the fingerprint uses the plugin id plus the URL path without the query string.
5. Add job `dast-web` to `factory.yml` (needs `setup`, web only). It runs harness up, the stage, and harness down (with `if: always()`), uploads the HTML report too, and is added to the gate's needs and to `factory/stage_matrix.py` for web.
6. Tests: unit tests for the ZAP JSON to findings conversion, using a small fixture report, and for the harness command builder (it asserts `--internal`, `--read-only` and `--cap-drop ALL` are present).

## Outputs
`factory/dast/__init__.py`, `factory/dast/harness.py`, `factory/stages/dast_web.py`, `zap/baseline.yaml`, `tests/test_dast_web.py`, `tests/fixtures/zap/`, and updated `tools/versions.lock`, `factory.yml` and `factory/stage_matrix.py`.

## Done when
- The latest `factory-test-web` run has a green `dast-web` job. Its artifact contains the ZAP HTML report and a `findings.json` with only `low`/`info` findings (helmet sets the headers), and the gate passes.
- The `dast-web` log shows the network created with `--internal`, and the app health check passing before ZAP starts.
- Selftest is green, including the conversion tests.

## Size
M

## Dependencies
- Needs: 06.
- Parallel: 07, 08, 09, 10, 11, 15.

## Background

### From the design document
> "DAST attacks the running app from the outside, the way a real attacker would, and finds problems that only appear at runtime such as missing security headers, weak session handling or exposed endpoints."

> "OWASP ZAP: the standard free choice. Recommended primary."

> "Setup: the factory builds the app into a container and starts it as a throwaway test instance, never against anything real."

> "Baseline scan first: passive checks only, fast and safe."

> "Some tools run from a container image instead, which is the usual route for OWASP ZAP, since the image bundles everything it needs."

### Decisions that apply
- D11: ZAP only (Nuclei later). Baseline first; the active scan and OpenAPI import come in chunk 13; authenticated scanning in chunk 25.
- Web DAST runs only when `.factory.yml` has `platform: web`.

### Pipeline architecture (decided)
- **Project stub** `.github/workflows/factory.yml` in each project repo. It triggers on:
  - `push` and `pull_request` (check mode; pushes to `factory/**` and `factory-record` are ignored),
  - `issues: [labeled]` with label `factory:spec` (spec mode) or `factory:change` (change mode),
  - `repository_dispatch` type `factory-fix` (fix mode).
  It calls `AakashDadhich/security-factory/.github/workflows/factory.yml@v1` (`@main` until chunk 30) with `secrets: inherit` and inputs `mode`, `factory-ref` and `config-path`.
- **Job graph.** `authorize → plan → threat-model → codegen-ai → codegen-commit → review` run in sequence (plan and codegen only in spec, change and fix modes). Then the security stages fan out in parallel: `secrets`, `sast-semgrep`, `sast-codeql`, `sast-eslint` (web), `deps-sbom`, and `dast-web` (web) or `apple-build` (with apple-checks), `sast-swiftlint`, `sast-codeql-swift`, `mobsf` (Apple). Then `gate` waits for all of them and merges their findings. Then `next-step` (fix loop) and `record`.
- **Fix loop (D16).** A failed gate with iteration < 2 sends `repository_dispatch` `factory-fix` with `{issue, iteration, findings_run_id}`. At the cap, the factory comments the report on the issue, labels it `factory:needs-human` and stops. There's one concurrency group per issue.
- **Project record (D15).** The living plan and threat model are committed with the code under `security/`. The orphan branch `factory-record` holds `runs/` history for every gate result, and `latest/` (SBOM, merged findings, run manifest) after each gate pass on the default branch.
- **Code landing (P4).** The bot commits only to `factory/<issue>`, never to the default branch. The owner merges.
- **AI in check mode (D18).** The AI stages run on PRs and default-branch pushes only. Fork PRs skip them. Spec and change modes run only if the triggering user is in repo variable `FACTORY_ALLOWED_ACTORS`.
- **Credentials.** There are no organisation secrets (D21): every repo that runs the factory, including `security-factory` itself, holds its own copies, set by the per-repo setup loop. `CLAUDE_CODE_OAUTH_TOKEN` is a repo secret (also a Dependabot repo secret). The GitHub App ID is repo variable `FACTORY_APP_ID`, and its private key is repo secret `FACTORY_APP_PRIVATE_KEY`, used only by the non-AI jobs `codegen-commit`, `next-step` and `record`.
- **`.factory.yml` shape** in each project:
```yaml
platform: web            # web | macos | ios
asvs_level: null         # 1 | 2 | 3, or null for the D2 rule
web:
  port: 3000
  health_path: /health
  openapi: openapi.yaml  # optional
  dockerfile: Dockerfile
apple:
  project_spec: project.yml   # XcodeGen spec
  scheme: App
```

### Factory facts (shared by every chunk)
- The factory is one public GitHub repo, `AakashDadhich/security-factory` (a personal account, no organisation; see D21), checked out at `/Users/aakash/Documents/projects/secure-software-factory`. One factory serves every project: iOS, macOS and web apps.
- The orchestrator is plain deterministic Python, not an AI. AI runs only inside specific stages, always through the model adapter `python -m factory.adapter`. Prompts and rules are plain text files in the factory repo.
- Repo layout: `factory/` (Python 3.12 package), `prompts/`, `rules/`, `schemas/`, `semgrep-rules/`, `tools/versions.lock`, `Makefile`, `tests/`, `docs/`, `.github/workflows/factory.yml` (the reusable pipeline, `on: workflow_call`), `.github/workflows/selftest.yml` (the factory's own tests), `.github/actions/` (composite actions), `templates/project/`.
- Make targets are thin wrappers around `python -m factory.<module>`. Tests are pytest and run in `selftest.yml` on GitHub. Don't install tools on the owner's Mac. Verify by pushing (after asking) and reading CI results with `gh run view`.
- Runners: GitHub-hosted only. `ubuntu-24.04` for everything except Apple build stages, which use `macos-15`.
- Tools are installed on runners with `python -m factory.tools install <name>`, which reads the exact version, URL and SHA-256 or container digest from `tools/versions.lock` and refuses a mismatch. Third-party actions are pinned by full commit SHA.
- Pipeline jobs check out the factory at `inputs.factory-ref` into `.factory/` and then use `./.factory/.github/actions/setup-factory`.
- Stage contract: each stage writes to `out/<stage>/`: `findings.json` (an array of findings matching `schemas/finding.schema.json`), plus raw SARIF 2.1.0 or CycloneDX JSON where relevant. The job uploads `out/<stage>/` as artifact `<stage>`.
- Finding fields (schema defined in chunk 03): `id`, `stage`, `tool`, `source` (`scanner`, `ai-review`, `ai-threat-model` or `check`), `rule_id`, `title`, `severity` (`critical`, `high`, `medium`, `low` or `info`), `location` (`{path, start_line, end_line}` or `{url, method}`), `cwe` (list), `description`, `remediation`, `fingerprint` (stable across runs).
- Workflow security: top-level `permissions: {}`, and each job grants only what it needs. AI jobs get `contents: read` and never the GitHub App key. Never put `${{ github.event.* }}` text directly into a `run:` script; pass it through `env:`.
- Owner conventions: Conventional Commits; no em dashes in anything written; no code comments unless genuinely non-obvious; tests for all new logic; ask before any push, repo creation or GitHub settings change.
