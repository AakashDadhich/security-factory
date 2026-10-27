# 19. Secure code generation

## Goal
The coding agent implements the plan on branch `factory/<issue>`, constrained by the rendered security rules and the threat model's mitigations. Pre-commit hooks (Semgrep and Gitleaks) block insecure code before it's committed, and the bot commits and pushes without the AI ever holding a write credential.

## Inputs
- `plan/PROGRESS.md`
- From chunk 15: `python -m factory.rules render`
- From chunks 16 to 18: the `plan` and `threat-model` artifacts (`plan.json`, `tm.py`, `threats.json`, `attack-trees/`)
- From chunk 08: the Semgrep install and rule sets. From chunk 07: Gitleaks and `rules/gitleaks.toml`.
- From chunk 14: the App token pattern (`actions/create-github-app-token`)

## Tasks
1. Add lock entry `pre-commit` (pipx, exact version). Write `templates/precommit/.pre-commit-config.yaml` using only `repo: local` hooks that call the already-installed pinned `semgrep` (the factory rule sets for the platform, `--error`, `--metrics=off`) and `gitleaks` (`protect --staged` or the equivalent for the pinned version). No remote hook repos, which would be unpinned code.
2. Write `prompts/codegen.md`. Implement the requirements in `plan.json`, follow `CLAUDE.md`, and address each open mitigation. Add tests for new logic. Never add secrets or `.env` files. Touch only files inside the repo.
3. Write `factory/stages/codegen.py` for job `codegen-ai` (`contents: read`, Claude token only):
   1. Check out the project. Create or check out `factory/<issue>` from the default branch.
   2. Render `CLAUDE.md` and `AGENTS.md` at the repo root with platform, ASVS level and `threats.json`, and copy `plan.json`, `tm.py`, `threats.json` and `attack-trees/` into `security/`.
   3. Run the adapter with `--allow-write` and a narrow Bash allowlist per platform: for web, `npm ci`, `npm test`, `npx tsc`; for Apple, none (it builds in chunk 26).
   4. Stage all changes and run `pre-commit run` on the staged files. If blocked, send the hook output back to the agent and retry, at most 2 times. If still blocked, fail the stage with the hook output as findings (`source: check`, rule `precommit-blocked`, severity `high`).
   5. Write `out/codegen/changes.patch` (`git diff --binary --cached`) and `out/codegen/summary.json` (files changed, attempts).
4. Add job `codegen-commit` (no AI, needs `codegen-ai`, `contents: read`):
   - Mint an App token scoped to this repo.
   - Check out `factory/<issue>` fresh, apply `changes.patch`, re-run `pre-commit` (defence in depth), and refuse the patch if it touches `.github/` or any `.env*` other than `.env.example`.
   - Commit as the App bot with `feat: implement #<issue> (factory iteration <n>)` and push to `factory/<issue>`. The push target is never the default branch: assert the branch name pattern before pushing.
5. Wire the spec-mode job chain: `plan → threat-model → codegen-ai → codegen-commit`. The scanning jobs then check out `factory/<issue>` at the pushed commit, so pass the commit SHA as a job output.
6. Add both jobs to the stage matrix for spec, change and fix modes.
7. Tests: the patch path filter (`.github/` rejected); the branch-name assertion; the pre-commit retry loop (fake hook runner, fake adapter); rules rendering wired with the threats file.

## Outputs
`prompts/codegen.md`, `templates/precommit/.pre-commit-config.yaml`, `factory/stages/codegen.py`, `factory/stages/codegen_commit.py`, `tests/test_codegen.py`, and updated `factory.yml`, `factory/stage_matrix.py` and `tools/versions.lock`.

## Done when
- Selftest is green.
- Re-run the notes-feature spec issue in `factory-test-web`. Branch `factory/<issue>` exists with one bot commit containing source changes, tests, `CLAUDE.md`, `AGENTS.md` and `security/{plan.json,tm.py,threats.json}`, and the scanning jobs ran against that commit.
- `git log origin/main` in `factory-test-web` has no bot commits.
- The `codegen-ai` job's environment never contains `FACTORY_APP_PRIVATE_KEY`. Grep the workflow file: the secret appears only in `codegen-commit` and `record`.

## Size
L

## Dependencies
- Needs: 15, 17.
- Parallel: 18.

## Background

### From the design document
> "The goal is to constrain the coding agent so insecure code is unlikely to be written, then catch what slips through before it lands."

> "A security rules file for Claude Code: a project instruction file that bakes in the OWASP Top 10, the ASVS requirements for the chosen level, and the specific mitigations from this project's threat model. Recommended base layer."

> "Pre-commit hooks: Semgrep and Gitleaks run automatically on every commit, so insecure code or a leaked key is blocked before it enters the repo."

> "Claude's CLAUDE.md file then becomes just one rendering of those neutral rules, generated from them. The AGENTS.md convention, which several coding tools read, can be another."

### Decisions that apply
- D5: rules file + secure-by-default patterns + pre-commit hooks (on the runner, bot commits only) + second-agent review (chunk 20).
- P4: direct commits by the bot to `factory/<issue>`, never to the default branch. The owner merges.
- D15: plan and threat model are committed with the code under `security/`.
- The AI job never holds the App key. A separate job with no AI applies the patch and pushes.

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
