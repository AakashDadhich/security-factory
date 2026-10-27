# 11. Gate and merged report

## Goal
Replace the stub gate with the real one. It merges every stage's findings into one deduplicated report, applies the severity policy and time-limited suppressions, fails closed when a stage is missing or broken, and becomes a required check on project repos.

## Inputs
- `plan/PROGRESS.md`
- From chunk 03: `factory/findings.py`, `schemas/*.json`
- From chunk 06: `factory/gate.py` (stub), `factory/config.py`, `schemas/factory-config.schema.json`
- From chunks 07 to 10: the stages `secrets`, `sast-semgrep`, `sast-codeql`, `sast-eslint` and `deps-sbom`

## Tasks
1. Write `factory/stage_matrix.py`, which lists the stages expected for each platform and mode. For example, web check mode expects secrets, sast-semgrep, sast-codeql, sast-eslint, deps-sbom, and later dast-web and the AI stages. Stages that are allowed to be skipped are listed with their reason (`fork-pr`, `not-applicable`). Later chunks add their stages here.
2. Write the gate, `factory/gate.py`, run as `python -m factory.gate --artifacts <dir> --config .factory.yml --manifest <path> --out out/gate`:
   - Load every `*/findings.json` and validate it. A missing, invalid or failed expected stage produces a blocking finding (`source: check`, rule `stage-missing` or `stage-failed`, severity `critical`). The gate fails closed.
   - Deduplicate across tools. Findings with the same path, overlapping lines and at least one shared CWE merge into one, keeping the highest severity and listing all tools.
   - Policy: factory `policy.yml` sets `fail_on: [critical, high]`. A project's `.factory.yml` may add `medium` under `policy.fail_on_extra`, but can never remove a level.
   - Suppressions: `.factory.yml` key `suppressions:`, a list of entries with `fingerprint`, `reason`, `expires` (ISO date, at most 90 days ahead) and `approved_by`. An expired or malformed suppression is ignored and itself reported as a `medium` finding. Suppressed findings stay in the report, marked as suppressed.
   - Write `out/gate/report.json` (all findings, merged), `out/gate/report.md`, `out/gate/gate-result.json` (`status`, counts by severity, blocking fingerprints, mode, iteration) and `out/gate/merged.sarif`.
   - Write `report.md` to `$GITHUB_STEP_SUMMARY`. Exit 1 on failure.
3. Extend `schemas/factory-config.schema.json` with `policy.fail_on_extra` and `suppressions`.
4. Gate job: upload `out/gate/` as artifact `gate`, and upload `merged.sarif` to code scanning with category `factory-gate` (job permission `security-events: write`).
5. Write `docs/required-check.md`, the steps to add a branch ruleset on a project's default branch that requires the `factory / gate` check. Ask the owner before applying it to `factory-test-web` with `gh api` (it's a GitHub settings change).
6. Tests: dedupe across Semgrep and CodeQL on the same line; policy tightening allowed and loosening rejected; suppression expiry; a missing stage fails closed; the stage matrix for web check mode.

## Outputs
`factory/gate.py`, `factory/stage_matrix.py`, `policy.yml`, `docs/required-check.md`, `tests/test_gate.py`, and updated `schemas/factory-config.schema.json` and `factory.yml`.

## Done when
- Selftest is green, with the gate tests covering all 5 cases in task 6.
- The latest `factory-test-web` run passes. Its summary shows the severity table and a "Stages" table with every expected stage `ok`.
- On a scratch branch in `factory-test-web`, deleting the `sast-semgrep` job's artifact upload makes the gate fail with `stage-missing` (simulate this in a test if editing the factory on a branch is easier). Revert afterwards.
- Once the owner approves the ruleset: `gh api repos/AakashDadhich/factory-test-web/rulesets` lists a ruleset requiring the gate check.

## Size
M

## Dependencies
- Needs: 07, 08, 09, 10.
- Parallel: 12, 13, 15.

## Background

### From the design document
> "The gate. All findings from every stage are merged into one report. High-severity findings fail the build and loop back to code generation; a clean report ships the project and saves the threat model, SBOM and findings as its record."

> "GitHub Actions. Each stage is a job, the gate is a required check, and Actions stores artifacts such as the SBOM and report for you. Free for public repositories."

> "The gate job waits for all three and merges their results. The slowest scan sets the pace instead of all of them adding up."

### Decisions that apply
- D19: high and critical findings from the AI review block the gate like scanner findings, and can be suppressed with a reason and expiry.
- P1: public repos, so rulesets and code scanning uploads are free.
- Later chunks add stages to `factory/stage_matrix.py`: DAST (12), the AI stages (16 to 20) and Apple (26 to 28).

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
