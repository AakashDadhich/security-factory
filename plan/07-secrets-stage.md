# 07. Secrets stage

## Goal
Scan the project's full git history for committed secrets with Gitleaks, flag any committed `.env` file, and emit findings the gate understands.

## Inputs
- `plan/PROGRESS.md`
- From chunk 02: `factory/tools.py`, `tools/versions.lock` (already has `gitleaks`)
- From chunk 03: `factory/sarif.py`, `factory/findings.py`
- From chunk 06: `.github/workflows/factory.yml` with jobs `setup` and `gate`

## Tasks
1. Write `factory/stages/secrets.py`, run as `python -m factory.stages.secrets --repo . --out out/secrets`:
   - Run the pinned Gitleaks binary over the whole history (`gitleaks git`, check the subcommand name for the pinned version) with SARIF output to `out/secrets/gitleaks.sarif`, the factory config `rules/gitleaks.toml` (Gitleaks defaults plus `[extend] useDefault = true`), and redaction on.
   - Treat Gitleaks' "leaks found" exit code as success with findings. Treat any other non-zero exit as a stage failure.
   - Convert the SARIF to findings (stage `secrets`, tool `gitleaks`, severity `high` for every secret).
   - Add the env-file check: any tracked file matching `(^|/)\.env(\.[^/]*)?$` other than `.env.example` produces a finding with source `check`, rule `committed-env-file`, severity `high`.
   - Write `out/secrets/findings.json`.
2. Add job `secrets` to `factory.yml`: needs `setup`, checks out with `fetch-depth: 0`, installs Gitleaks, runs the stage, uploads the artifact. Add `secrets` to the gate's `needs`.
3. Add a `secrets-integration` job to selftest that installs Gitleaks. In a temp dir it creates a git repo with one commit containing a fake generic API key (`api_key = "<32 random hex chars>"`, made up at test time and never committed to a real repo) and a `.env` file. It runs the stage and asserts exactly 2 findings.
4. Add unit tests for the env-file matcher (`.env`, `config/.env.local` match; `.env.example`, `env.ts` don't) and for exit code handling.

## Outputs
`factory/stages/__init__.py`, `factory/stages/secrets.py`, `rules/gitleaks.toml`, `tests/test_secrets.py`, and updated `factory.yml`, `selftest.yml` and `Makefile` (target `secrets`).

## Done when
- The selftest run is green, including `secrets-integration`, which asserts 2 findings.
- The latest `factory-test-web` run has a green `secrets` job and the gate passes. The `secrets` artifact contains `findings.json` with `[]`.
- `gitleaks.sarif` in the artifact contains no unredacted secret values. Check it with `grep -c REDACTED` on the integration test's SARIF.

## Size
S

## Dependencies
- Needs: 06.
- Parallel: 08, 09, 10, 12, 15.

## Background

### From the design document
> "Secrets detection. Finds keys and passwords that were committed by mistake."

> "Gitleaks: as a pre-commit hook, plus a full git history scan in the pipeline. Recommended primary."

> "Secrets management. Real secrets stay out of the repository entirely."

> "Once the code exists, SAST, dependency and secrets scanning with the SBOM, and DAST do not depend on each other, so they fan out and run side by side. The gate job waits for all three and merges their results."

### Decisions that apply
- D9: Gitleaks binary only. TruffleHog comes later. Every committed secret counts, live or not.
- D10: never commit `.env`. Only `.env.example` with fake values. GitHub push protection is also on, so tests must use generic patterns that push protection doesn't recognise, and must create them at test time rather than committing them.

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
