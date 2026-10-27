# 14. Project record

## Goal
Give every project a permanent, diffable record of its security runs. An orphan `factory-record` branch holds a history entry for every gate result, and the latest SBOM, findings and run manifest after each gate pass on the default branch, including what changed in the SBOM since last time.

## Inputs
- `plan/PROGRESS.md` (App variable and secret names in Notes)
- From chunk 03: `factory/sbom.py` (`diff`), `schemas/run-manifest.schema.json`
- From chunk 11: `factory/gate.py` and its outputs `gate-result.json`, `report.json`
- From chunk 10: the `deps-sbom` artifact with `sbom.cdx.json`

## Tasks
1. Write `factory/record.py`:
   - `python -m factory.record read --repo <owner/name> --out <dir>` fetches `factory-record` (shallow) if it exists and copies `latest/` and the last 10 `runs/` entries into `<dir>`. If the branch doesn't exist, it creates an empty dir.
   - `python -m factory.record write --repo <owner/name> --artifacts <dir> --event <push|pull_request|...> --ref <ref> --default-branch <name>`:
     - Always: add `runs/<UTC timestamp>-<run_id>.json` containing mode, ref, commit, gate status, counts, blocking fingerprints, iteration and issue.
     - Only when the gate passed on a push to the default branch: replace `latest/` with `sbom.cdx.json`, `findings.json` (the merged report, including suppressed findings), `run-manifest.json` and `sbom-diff.json` (compared with the previous `latest/sbom.cdx.json`).
     - Create the orphan branch on first use. Commit as the App bot with message `chore(record): <mode> run <run_id> <status>`. On a push race, retry up to 3 times with fetch and rebase; files are append-only or wholly replaced, so they never conflict.
2. Add job `record` to `factory.yml`: needs `gate`, `if: always() && needs.gate.result != 'skipped'`.
   - Mint a short-lived App token with `actions/create-github-app-token` (pinned SHA), using `FACTORY_APP_ID` and `FACTORY_APP_PRIVATE_KEY`, scoped to the current repo.
   - Download the `gate` and `deps-sbom` artifacts and run `record write`. Nothing else runs in this job.
3. Make sure the stub template, and the `factory-test-web` stub, have `factory-record` in the push `branches-ignore`.
4. Write `docs/record.md`: the layout of the record branch, and how the improvement loop and the plan stage read it.
5. Tests: `runs/` entry naming, the `latest/` update rule (only on a default-branch push pass), the SBOM diff written correctly, and retry on a simulated non-fast-forward (using a temp bare git repo as the remote).

## Outputs
`factory/record.py`, `docs/record.md`, `tests/test_record.py`, and updated `factory.yml` and the stub template.

## Done when
- After a push to `main` on `factory-test-web`: `gh api repos/AakashDadhich/factory-test-web/branches/factory-record` exists, and `gh api 'repos/AakashDadhich/factory-test-web/contents/latest/sbom.cdx.json?ref=factory-record'` returns a file.
- The `runs/` folder on that branch has one entry per run, and no new workflow run was triggered by the record push (`gh run list` shows no run for branch `factory-record`).
- After a second push that changes a dependency, `latest/sbom-diff.json` lists the change.
- Selftest is green.

## Size
M

## Dependencies
- Needs: 11.
- Parallel: 13, 15.

## Background

### From the design document
> "A pass ships the project and writes the findings and threat model into the project's record. When you later want a change, a new spec or change request enters at the top again. The factory reads the existing threat model and findings first, updates the threat model for what the change touches, and then runs a full security re-run of every stage, not a targeted one."

> "Store each SBOM with the project record so a later run can show what changed."

> "The green dashed line is the outer improvement loop: a shipped project's saved record feeds the next change request."

### Decisions that apply
- D15: two parts. The living plan and threat model are committed with the code under `security/` (by chunk 19), so they merge with it. The orphan branch `factory-record` holds the run history: `runs/` for every gate result, and `latest/` updated on each gate pass of a default-branch push. Pushes to `factory-record` never trigger runs.
- Only this job and the codegen commit job ever hold an App token. AI jobs never do.

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
