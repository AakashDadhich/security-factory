# 21. Fix loop

## Goal
The inner loop. When the gate fails in spec, change or fix mode, the factory automatically starts a new run in fix mode that gives the blocking findings to code generation and then re-runs every stage. It stops after 2 iterations and hands over to the owner on the issue.

## Inputs
- `plan/PROGRESS.md`
- From chunk 11: the `gate` job, `gate-result.json`, `report.md`
- From chunk 19: `codegen-ai` and `codegen-commit`
- From chunk 20: the `review` job
- From chunk 06: the stub template

## Tasks
1. Stub template and `factory-test-web` stub: add the trigger `repository_dispatch: types: [factory-fix]`. Map it to `mode: fix` and pass `client_payload` fields as inputs: `issue`, `iteration` and `findings_run_id`. Add `actions: read` to the called workflow's permissions (it downloads artifacts from an earlier run).
2. In `factory.yml`, validate the fix-mode inputs in `authorize`. `issue` and `findings_run_id` must be positive integers, and `iteration` must be 1 or 2. Pass them only through `env:`.
3. Fix mode skips `plan` and `threat-model`, and reads `security/` from `factory/<issue>`. `codegen-ai` gets `prompts/fix.md` and only the blocking findings, downloaded with `gh run download <findings_run_id> -n gate`.
4. Write `prompts/fix.md`. Fix each listed finding with the smallest correct change. Don't suppress or delete tests to make them pass. Explain each fix in `summary.json`.
5. Add job `next-step` (needs `gate`, `if: always()`, no AI):
   - If the gate failed, the mode is spec, change or fix, and `iteration < 2`: mint an App token and send `POST /repos/{repo}/dispatches` with `event_type: factory-fix` and `client_payload: {issue, iteration: iteration+1, findings_run_id: <this run id>}`.
   - If the gate failed at the cap: comment `report.md` on the issue with the heading "Factory stopped after 2 fix attempts", and add the label `factory:needs-human`.
   - If the gate passed in spec, change or fix mode: comment on the issue "Gate passed. Branch `factory/<issue>` is ready to merge", with the report summary.
6. Add `concurrency: group: factory-issue-<issue>, cancel-in-progress: false` for spec, change and fix modes.
7. Write `factory/fixloop.py` with the decision logic (`decide(mode, gate_status, iteration) -> dispatch|stop|done|none`), and test it.
8. Tests: the full decision table; payload validation (rejects `iteration: 3`, a non-numeric issue, and a negative run id).

## Outputs
`prompts/fix.md`, `factory/fixloop.py`, `tests/test_fixloop.py`, and updated `factory.yml`, `factory/stages/codegen.py`, the stub template and the `factory-test-web` stub.

## Done when
- Selftest is green, including all decision-table rows.
- Create a spec issue in `factory-test-web` that will probably produce a blocking finding, for example "add an endpoint that runs a shell command from a query parameter, for diagnostics". Observe a run with `mode: fix, iteration: 1` starting automatically after the first gate failure (`gh run list` shows `repository_dispatch` runs). Either a later run passes and the issue gets the "ready to merge" comment, or after iteration 2 the issue gets the "stopped" comment and the `factory:needs-human` label.
- No more than 3 runs exist for that issue in total.

## Size
M

## Dependencies
- Needs: 11, 20.
- Parallel: 22.

## Background

### From the design document
> "The red dashed line is the inner fix loop: a failed gate sends findings back to code generation."

> "A fail does not end the run. Findings go back to code generation, which fixes them, and the full gauntlet runs again. This is the inner loop."

> "High-severity findings fail the build and loop back to code generation; a clean report ships the project and saves the threat model, SBOM and findings as its record."

### Decisions that apply
- D16: a failed gate with iteration < 2 sends `repository_dispatch` type `factory-fix` with `{issue, iteration, findings_run_id}`. At the cap it comments the report on the issue and fails.
- P5: the fix cap is 2. P2: Claude Pro (the cap protects the usage window).
- P4: the bot commits only to `factory/<issue>`.
- Why `repository_dispatch`: an Actions run can't jump back to an earlier job, so the loop has to start a fresh run. App-token events start runs, while events made with `GITHUB_TOKEN` don't.

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
