# 05. Web test project

## Goal
A small, clean Node + Express TypeScript app in its own public repo that the factory runs against. It should pass every security stage once they exist.

## Inputs
- `plan/PROGRESS.md` (owner and repo names in Notes)
- The public repo `AakashDadhich/factory-test-web` (created empty in chunk 00)

## Tasks
1. Clone the repo to `/Users/aakash/Documents/projects/factory-test-web` with `gh repo clone`.
2. Build the app: Express (latest stable 5.x) with TypeScript, written with secure defaults:
   - `GET /health` returns `{"status":"ok"}`.
   - `GET /api/greeting?name=` validates `name` (letters only, max 40 characters) and returns JSON.
   - Uses `helmet` for security headers, sets no cookies, has a JSON body size limit, and doesn't send the `x-powered-by` header.
3. Add `npm test` using Node's built-in test runner and `supertest`. Cover health, a valid greeting, a rejected greeting, and the presence of the security headers.
4. Add a multi-stage `Dockerfile`: build stage, runtime stage on a `node:22-slim` image pinned by digest, a non-root user, `EXPOSE 3000`, and `HEALTHCHECK` on `/health`.
5. Add `openapi.yaml` (OpenAPI 3.1) describing both endpoints.
6. Add `.factory.yml` using the shape under Pipeline architecture below (`platform: web`, port 3000, health path `/health`, openapi `openapi.yaml`, dockerfile `Dockerfile`, `asvs_level: null`).
7. Add `.env.example` containing only `PORT=3000`, plus a `.gitignore` that ignores `.env` and `node_modules/`.
8. Add `.github/dependabot.yml` with ecosystems `npm`, `docker` and `github-actions`, checked weekly.
9. Add `.github/workflows/app-ci.yml`: on push and PR, run `npm ci`, `npm test` and `docker build` on `ubuntu-24.04`, with `permissions: contents: read` and actions pinned by SHA.
10. Commit `package-lock.json`. Ask the owner, then push.

## Outputs
In `AakashDadhich/factory-test-web`: `src/`, `test/`, `package.json`, `package-lock.json`, `tsconfig.json`, `Dockerfile`, `openapi.yaml`, `.factory.yml`, `.env.example`, `.gitignore`, `.github/dependabot.yml`, `.github/workflows/app-ci.yml`, `README.md`.

## Done when
- `gh run list --repo AakashDadhich/factory-test-web --workflow app-ci.yml --limit 1` shows success.
- The CI log shows all 4 tests passing and the Docker image building.
- `.factory.yml` parses as YAML with `platform: web`.
- `git -C /Users/aakash/Documents/projects/factory-test-web ls-files | grep -x .env` prints nothing.

## Size
S

## Dependencies
- Needs: 00.
- Parallel: 02, 03, 04.

## Background

### From the design document
> "Setup: the factory builds the app into a container and starts it as a throwaway test instance, never against anything real."

> "API spec import: if the app has an OpenAPI spec, feed it to ZAP so every endpoint gets tested."

> "Dependabot (free on GitHub): opens update pull requests automatically when a fix is available."

### Decisions that apply
- P7: Node + Express, TypeScript.
- D7: Dependabot is on for every project.
- D10: commit only `.env.example`, with fake values. Never commit `.env`.
- D11: ZAP runs against a container of this app, and imports `openapi.yaml`.

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
