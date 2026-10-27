# 24. Improvement loop

## Goal
The outer loop. A change request (an issue labelled `factory:change`) on an existing project reads the project's existing plan, threat model and record first, plans the change, updates the threat model for what the change touches, generates code, and then re-runs every security stage.

## Inputs
- `plan/PROGRESS.md`
- From chunk 14: `python -m factory.record read` (gives `latest/` and recent `runs/`)
- From chunk 16: the plan stage and the `factory:change` label mapping
- From chunks 17 and 18: the threat model stage with update mode
- From chunks 19 to 21: codegen, review, fix loop

## Tasks
1. Write `prompts/plan-change.md`. The input is the change request, the current `security/plan.json`, `latest/findings.json` from the record, and the last 3 failed `runs/` entries. The output uses the plan schema plus `changed_features[]` and `touched_elements[]` (pytm element names).
2. Extend `schemas/plan.schema.json` with optional `changed_features` and `touched_elements`, so spec mode stays valid.
3. In `factory/stages/plan.py`, change mode: read the record with `record read`, read `security/plan.json` from the default branch, and run the change prompt. The output is a full updated plan (unchanged features kept with stable ids), and the ASVS level can only stay the same or go up.
4. In `factory/stages/threat_model.py`, change mode: pass `touched_elements` so the STRIDE pass focuses on them, but keep the full `threats.json` (untouched threats carried over with stable ids). Re-run LINDDUN and attack trees by the same D3 rules.
5. Make sure the change-mode job chain is `authorize → plan → threat-model → codegen-ai → codegen-commit → review → every scanner → gate → next-step → record`. Assert in a test, using `factory/stage_matrix.py`, that change mode expects every stage that spec mode expects, so there are no targeted re-runs.
6. On a gate pass, the issue comment (from chunk 21) also includes a threat-model diff summary (threats added, changed, removed) and, after merge, the SBOM diff from the record.
7. Tests, using the fake adapter: ASVS never decreases; stable threat ids; the change-mode stage set equals the spec-mode set; record inputs are passed to the prompt.

## Outputs
`prompts/plan-change.md`, `factory/threatmodel/diff.py` (threats diff), `tests/test_change_mode.py`, and updated `schemas/plan.schema.json`, `factory/stages/plan.py`, `factory/stages/threat_model.py`, `factory/stage_matrix.py` and `factory.yml`.

## Done when
- Selftest is green.
- On `factory-test-web`, after the notes feature has been merged to `main` and passed (so the record and `security/` exist), open an issue "Rate-limit the notes endpoints" labelled `factory:change`. The run's manifest says `mode: change`, every stage in the matrix ran, `security/threats.json` on `factory/<issue>` keeps the old threat ids, and it adds or updates at least one threat on the touched element.
- The issue's pass comment shows the threat-model diff.

## Size
M

## Dependencies
- Needs: 21, 22.
- Parallel: 25, 26.

## Background

### From the design document
> "A pass ships the project and writes the findings and threat model into the project's record. When you later want a change, a new spec or change request enters at the top again. The factory reads the existing threat model and findings first, updates the threat model for what the change touches, and then runs a full security re-run of every stage, not a targeted one. This is the outer loop, and it is what makes the factory recursive."

> "The green dashed line is the outer improvement loop: a shipped project's saved record feeds the next change request."

### Decisions that apply
- P3: change requests are issues labelled `factory:change`.
- D15: the plan and threat model live in `security/` on the default branch after merge. Run history is on `factory-record`.
- D2: the ASVS level never goes down. D3: the LINDDUN and attack-tree triggers are the same as in spec mode.

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
