# 22. Check mode wiring

## Goal
Make check mode complete and correct for every push and pull request. Scanners and the gate always run. The threat-model update and the second-agent review run on PRs and default-branch pushes. Fork PRs and Dependabot PRs are handled safely.

## Inputs
- `plan/PROGRESS.md`
- From chunk 11: the gate and `factory/stage_matrix.py`
- From chunk 14: `python -m factory.record read`
- From chunk 17 and 18: `factory/stages/threat_model.py`
- From chunk 20: `factory/stages/review.py`

## Tasks
1. Add job `ai-eligible` in `factory.yml` (no AI, outputs `run_ai` and `reason`). `run_ai` is true only when all of these hold:
   - the event is `pull_request`, or a `push` to the repository's default branch,
   - the PR head repo isn't a fork,
   - the Claude secret is available.
   For Dependabot PRs, the Dependabot secret makes it available. Otherwise `reason` is `work-in-progress-push`, `fork-pr` or `no-secret`.
2. Check mode, when `run_ai` is true:
   - `threat-model` runs in update mode. Input is the current `security/tm.py` and `security/threats.json` if they exist, plus the diff. If none exist, it bootstraps a model from the code without a plan.
   - `review` runs on the PR or push diff.
   - Neither commits anything. Results are artifacts, and the record stores them on default-branch passes.
3. When `run_ai` is false, the AI jobs are skipped, and `factory/stage_matrix.py` treats them as allowed skips with that reason. The gate summary shows "AI stages skipped: <reason>".
4. Make sure fork PRs never get secrets or write permissions. They are never `pull_request_target`, and the stub uses plain `pull_request`. Document why in `docs/pipeline.md`.
5. Bring `docs/pipeline.md` up to date with a Mermaid job graph for each mode (spec, change, fix, check).
6. Tests: the `ai-eligible` truth table, covering every reason; the stage matrix allowing the AI skips only for those reasons; the gate summary text.

## Outputs
Updated `factory.yml`, `factory/stage_matrix.py`, `factory/stages/threat_model.py` (bootstrap and update without a plan), `docs/pipeline.md`, and a new `factory/eligibility.py` and `tests/test_eligibility.py`.

## Done when
- Selftest is green.
- On `factory-test-web`, a push to a feature branch runs scanners and gate, but not the AI jobs (summary shows `work-in-progress-push`). Opening a PR from that branch runs `threat-model` and `review` too.
- A Dependabot PR on `factory-test-web` (trigger one via Insights > Dependency graph > Dependabot, or wait for the weekly run) runs the full check-mode pipeline. If none arrives in the session, record this check as pending in PROGRESS.md.
- `grep -n pull_request_target` over the factory and stub workflows finds nothing.

## Size
M

## Dependencies
- Needs: 11, 14, 18, 20.
- Parallel: 21.

## Background

### From the design document
> "Every change to an existing project triggers a full re-run of every stage, not a targeted one."

> "Once the code exists, SAST, dependency and secrets scanning with the SBOM, and DAST do not depend on each other, so they fan out and run side by side. The gate job waits for all three and merges their results."

### Decisions that apply
- P3: check mode runs on every push and PR.
- D18: the threat-model update and second-agent review run on PRs and default-branch pushes only. Scanners and gate run on every push. This is the one deliberate exception to "every stage on every change", made to save Pro usage. Default-branch pushes and PRs still get every stage.
- D19: AI review findings block like scanner findings.
- Dependabot PRs can't read Actions secrets. The Claude token is also a Dependabot repo secret in every factory repo (set by the per-repo setup loop from chunk 00).

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
