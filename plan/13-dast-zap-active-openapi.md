# 13. DAST: ZAP active scan and OpenAPI import

## Goal
Extend web DAST so that after the passive baseline, ZAP imports the project's OpenAPI spec when there is one and runs a time-boxed active scan with real attack payloads, only against the throwaway container.

## Inputs
- `plan/PROGRESS.md`
- From chunk 12: `factory/dast/harness.py`, `factory/stages/dast_web.py`, `zap/baseline.yaml`, the `dast-web` job
- From chunk 06: `factory/config.py` (`web.openapi` is optional)
- Project `factory-test-web` with `openapi.yaml`

## Tasks
1. Write `zap/full.yaml`, an Automation Framework plan with these jobs in order:
   - `openapi`: only included when `web.openapi` is set. The spec is mounted read-only, and `targetUrl` is overridden to `http://app:<port>`.
   - `spider`, bounded.
   - `passiveScan-wait`.
   - `activeScan`, using the default policy with `maxRuleDurationInMins: 2` and `maxScanDurationInMins: 15`.
   - `passiveScan-wait`.
   - `report`, in JSON and HTML.
2. Generate the plan from a template in `factory/dast/plan.py` (deterministic, so it can be unit tested), so that the `openapi` job appears only when configured.
3. Make the stage run `full` by default and keep `--plan baseline` for debugging. Add a guard that refuses to run if the target host isn't `app` on the `factory-dast` network, so the active scan can never be pointed at a real host.
4. Set the `dast-web` job's `timeout-minutes` to 30.
5. Tests: plan generation with and without OpenAPI; the guard rejects `http://example.com`; a fixture report from an active scan converts with the correct risk mapping.

## Outputs
`zap/full.yaml` (template), `factory/dast/plan.py`, `tests/test_dast_plan.py`, and updated `factory/stages/dast_web.py` and `factory.yml`.

## Done when
- The latest `factory-test-web` `dast-web` log shows the `openapi` job importing 2 endpoints and the `activeScan` job completing, with the job finishing in under 20 minutes.
- The ZAP JSON report in the artifact contains URLs for both `/health` and `/api/greeting`.
- The gate passes on the clean app.
- Selftest is green, including the guard test.

## Size
M

## Dependencies
- Needs: 12.
- Parallel: 11, 14, 15.

## Background

### From the design document
> "Active scan second: runs real attack payloads, against the throwaway instance only."

> "API spec import: if the app has an OpenAPI spec, feed it to ZAP so every endpoint gets tested."

> "Setup: the factory builds the app into a container and starts it as a throwaway test instance, never against anything real."

### Decisions that apply
- D11: ZAP only. OpenAPI import is built from the start. Authenticated scanning is a later chunk (25).

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
