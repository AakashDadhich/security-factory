# 25. ZAP authenticated scanning

## Goal
Let ZAP log in to the throwaway app with a seeded test user, so it scans the pages behind sign-in. Prove it on the vulnerable app by catching a flaw that only exists behind the login.

## Inputs
- `plan/PROGRESS.md`
- From chunk 13: `factory/dast/plan.py`, `zap/full.yaml` template, the guard
- From chunk 12: `factory/dast/harness.py`
- From chunk 23: `factory-vuln-web`, `expected-findings.yml`, `factory/acceptance.py`

## Tasks
1. Extend the `.factory.yml` schema with an optional `web.auth`:
   - `type`: `form` or `json`
   - `login_url`, `username_field`, `password_field`
   - `username_env` and `password_env` (names of variables in `.env.example`)
   - `logged_in_regex`, `logged_out_regex`
2. Harness: when `web.auth` is set, start the app with `SEED_TEST_USER=1` and the test credentials taken from `.env.example`. These are fake test values for the throwaway container only; real credentials are never used.
3. Plan generator: add a ZAP context with the authentication method (form- or JSON-based), a user, session management, and verification using the regexes. The spider and active scan run as that user. Keep the target guard.
4. In `factory-vuln-web`:
   - Add `/login` (JSON) and `/account/notes?q=`, which has reflected XSS and is reachable only when logged in.
   - Seed the user at startup when `SEED_TEST_USER=1`, with credentials from env.
   - Add `TEST_USERNAME=zap-test` and `TEST_PASSWORD=<random test value>` to `.env.example`.
   - Add an expectation: the dast-web finding CWE-79 on URL path `/account/notes`.
5. Tests: plan generation with auth (snapshot); auth omitted when not configured; the schema rejects an auth block with missing env names.

## Outputs
Updated `schemas/factory-config.schema.json`, `factory/dast/plan.py`, `factory/dast/harness.py`, `tests/test_dast_plan.py`, and `factory-vuln-web` changes.

## Done when
- Selftest is green.
- `gh workflow run acceptance.yml` passes, and its table shows the `/account/notes` XSS caught by `dast-web`.
- The ZAP report in the `factory-vuln-web` run lists URLs under `/account/`.
- The clean `factory-test-web` (no `web.auth`) still passes its gate.

## Size
M

## Dependencies
- Needs: 23.
- Parallel: 24, 26.

## Background

### From the design document
> "Authenticated scanning: give ZAP a test login so it reaches pages behind sign-in, where most of the risk lives."

> "Setup: the factory builds the app into a container and starts it as a throwaway test instance, never against anything real."

### Decisions that apply
- D11: ZAP only. Authenticated scanning was deliberately deferred until after the basic DAST path and the acceptance test worked.
- D10: only fake values in `.env.example`, never a real secret.

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
