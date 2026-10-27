# 06. Walking skeleton

## Goal
The thinnest end-to-end path. A push to the test project wakes its stub, the stub calls the factory's reusable workflow, and a trivial stage plus one real AI call through the adapter pass data as artifacts to a stub gate, which passes.

## Inputs
- `plan/PROGRESS.md`
- From chunk 02: `.github/actions/setup-factory`, `factory/tools.py`, `tools/versions.lock`
- From chunk 03: `schemas/findings.schema.json`, `schemas/run-manifest.schema.json`, `factory/findings.py`
- From chunk 04: `python -m factory.adapter`, `prompts/hello.md`, `schemas/hello.schema.json`
- From chunk 05: `AakashDadhich/factory-test-web` with `.factory.yml`

## Tasks
1. Write `schemas/factory-config.schema.json` for `.factory.yml` (the shape is under Pipeline architecture below), and `factory/config.py`. `python -m factory.config --path .factory.yml` validates the file and writes the GitHub outputs `platform`, `asvs_level` and `openapi`.
2. Write `.github/workflows/factory.yml` as a reusable workflow (`on: workflow_call`):
   - Inputs: `mode` (default `check`), `factory-ref` (default `main` until chunk 30 sets up `v1`), `config-path` (default `.factory.yml`).
   - Secrets: `CLAUDE_CODE_OAUTH_TOKEN` (optional).
   - Top-level `permissions: {}`.
   - Job `setup`: check out the project and the factory, validate the config, write `out/setup/run-manifest.json`, and upload it.
   - Job `passthrough` (needs `setup`): read the manifest, write an empty `out/passthrough/findings.json`, and upload it.
   - Job `hello-ai` (needs `setup`): runs only when the Claude secret is present, calls the adapter with the hello prompt, and uploads the result.
   - Job `gate` (needs all, `if: always()`): download every artifact and run `python -m factory.gate`, which is a stub for now. It validates every `findings.json`, counts findings by severity, writes a Markdown summary to `$GITHUB_STEP_SUMMARY`, and exits 1 if any finding is `critical` or `high`. It also fails if any needed job failed.
3. Add the stub template `templates/project/.github/workflows/factory.yml`:
   - Triggers `push` (with `branches-ignore: ['factory/**', 'factory-record']`), `pull_request` and `workflow_dispatch`.
   - Calls `AakashDadhich/security-factory/.github/workflows/factory.yml@main` with `secrets: inherit` and `factory-ref: main`.
   - Grants the called workflow `contents: read`. Later chunks add more permissions.
4. Copy the stub into `factory-test-web`. Ask the owner, then push both repos.
5. Tests: `tests/test_config.py` (valid and invalid configs) and `tests/test_gate_stub.py` (severity counting and the exit code).
6. Write `docs/pipeline.md`, a job graph diagram in Mermaid showing the current skeleton.

## Outputs
In the factory: `.github/workflows/factory.yml`, `factory/config.py`, `factory/gate.py` (stub), `schemas/factory-config.schema.json`, `templates/project/.github/workflows/factory.yml`, `tests/test_config.py`, `tests/test_gate_stub.py`, `docs/pipeline.md`. In `factory-test-web`: `.github/workflows/factory.yml`.

## Done when
- `gh run list --repo AakashDadhich/factory-test-web --workflow factory.yml --limit 1` shows success, triggered by a push.
- `gh run view <id> --repo AakashDadhich/factory-test-web` shows the jobs `setup`, `passthrough`, `hello-ai` and `gate`, all green.
- `gh run download <id> --repo AakashDadhich/factory-test-web -n hello-ai` gives JSON that validates against `schemas/hello.schema.json`.
- The gate job summary shows a severity table with all zeros.
- Temporarily make `passthrough` emit one `high` finding on a scratch branch: the gate fails. Revert it afterwards.

## Size
M

## Dependencies
- Needs: 02, 03, 04, 05.
- Parallel: none. This is the integration point.

## Background

### From the design document
> "A push to a project repo wakes its stub, the stub calls the reusable workflow in the factory repo, and that workflow runs your scripts, which in turn run the AI and scanning tools."

> "Workflows are per repository by default, but you do not have to rebuild the factory for each project. Write the whole pipeline once in a central factory repo and mark it as a reusable workflow. Each project repo then holds only a tiny stub, a few lines long, that calls the factory pipeline and passes in settings such as platform and risk level. Update the central repo and every project picks up the change."

> "The orchestrator is plain code, not an AI: it decides which stage runs next, passes artifacts between stages and enforces the gate."

> "Each parallel job runs on its own fresh machine, so each fetches the code itself, and results travel between jobs as saved artifacts. This is another reason the structured output formats matter."

### Decisions that apply
- D17: in the end, project stubs call `@v1`. Until chunk 30 creates that tag, use `@main` and `factory-ref: main`.
- A `uses:` ref can't be an expression, so jobs check out the factory at `inputs.factory-ref` into `.factory/` and then use `./.factory/.github/actions/setup-factory`.
- A reusable workflow can't have more permissions than the caller grants, so the stub grants permissions explicitly.

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
