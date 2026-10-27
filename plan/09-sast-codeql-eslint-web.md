# 09. SAST: CodeQL and ESLint for web

## Goal
Add CodeQL's deeper data-flow analysis for JavaScript/TypeScript and ESLint security plugins to web projects. Both emit findings, and CodeQL also feeds GitHub's Security tab.

## Inputs
- `plan/PROGRESS.md`
- From chunk 03: `factory/sarif.py`
- From chunk 06: `factory.yml`, `factory/config.py`, `templates/project/.github/workflows/factory.yml`
- Project `factory-test-web` (TypeScript sources in `src/`)

## Tasks
1. Add job `sast-codeql` to `factory.yml` (needs `setup`, only when `platform == web`):
   - Use `github/codeql-action/init` and `analyze` pinned by SHA, with `languages: javascript-typescript`, `build-mode: none`, `queries: security-extended`.
   - Set `analyze` with `output: out/sast-codeql` and upload to code scanning.
   - Convert the SARIF with `python -m factory.sarif ... --stage sast-codeql --tool codeql`, and write `findings.json`.
   - Job permissions: `contents: read`, `security-events: write`.
2. Update the stub template and the `factory-test-web` stub to grant `security-events: write` to the called workflow.
3. Write the ESLint tooling inside the factory, at `tools/eslint/`: a `package.json` and committed `package-lock.json` with exact versions of `eslint`, `typescript-eslint`, `eslint-plugin-security`, `eslint-plugin-no-unsanitized` and `@microsoft/eslint-formatter-sarif`, plus `eslint.config.mjs`, which enables the recommended configs of both security plugins for `**/*.{js,ts,mjs,cjs}`.
4. Write `factory/stages/sast_eslint.py`, which runs `npm ci` in `.factory/tools/eslint`, then runs ESLint with `--config` pointing at the factory config (never the project's own config) over the project sources, with SARIF output. Convert to findings with stage `sast-eslint` and tool `eslint`. ESLint `error` severity maps to `medium` unless the rule is in an `escalate` list in `tools/eslint/severity.yml` (for example `security/detect-eval-with-expression` → `high`).
5. Add job `sast-eslint` (web only), and add both new jobs to the gate's needs. Use `if: always()` handling so a skipped job for another platform doesn't fail the gate.
6. Tests: a fixture JS file with `eval(req.query.x)` produces a high finding (an integration job in selftest that installs the eslint tooling). Add a unit test for the severity escalation.

## Outputs
`tools/eslint/{package.json,package-lock.json,eslint.config.mjs,severity.yml}`, `factory/stages/sast_eslint.py`, `tests/test_sast_eslint.py`, `tests/fixtures/eslint/`, and updated `factory.yml`, the stub template, the `factory-test-web` stub, `selftest.yml` and `Makefile`.

## Done when
- The latest `factory-test-web` run shows `sast-codeql` and `sast-eslint` green, and the gate passes.
- `gh api repos/AakashDadhich/factory-test-web/code-scanning/analyses --jq '.[0].tool.name'` prints `CodeQL`.
- The selftest ESLint integration job asserts the `eval` fixture yields 1 high finding.
- `grep -E 'uses: github/codeql-action/[a-z]+@[0-9a-f]{40}' .github/workflows/factory.yml` matches both CodeQL steps.

## Size
M

## Dependencies
- Needs: 06.
- Parallel: 07, 08, 10, 12, 15.

## Background

### From the design document
> "CodeQL: deeper at tracing how untrusted data flows through a program. Free for public repositories on GitHub, so it suits a portfolio project well."

> "ESLint security plugins: cheap extra coverage for JavaScript and TypeScript web projects."

> "Because tools overlap but also miss different things, running Semgrep and CodeQL together gives better coverage than either alone. The gate fails the build on any high-severity finding."

### Decisions that apply
- D6: Semgrep + CodeQL + ESLint security plugins for web. CodeQL Swift is in chunk 26.
- P1: all repos are public, so CodeQL and the Security tab are free.

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
