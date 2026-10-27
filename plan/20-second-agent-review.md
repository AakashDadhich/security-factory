# 20. Second-agent security review

## Goal
A separate AI pass whose only job is to review the diff adversarially against the threat model and the ASVS checklist before the scanners run. It produces findings the gate judges like any scanner's.

## Inputs
- `plan/PROGRESS.md`
- From chunk 19: the `codegen-commit` job and its pushed commit SHA output, `security/` files on the branch
- From chunk 15: `python -m factory.rules checklist`
- From chunk 04: the adapter. From chunk 03: `factory/findings.py`.

## Tasks
1. Write `schemas/review.schema.json`: `findings[]` with `title`, `severity`, `path`, `start_line`, `end_line`, `cwe[]`, `asvs_refs[]`, `threat_ids[]`, `description`, `remediation`, `confidence` (low/medium/high).
2. Write `prompts/security-review.md`. You are an adversarial security reviewer, not the author. Review only the diff provided. Check each change against the threat model's open threats and the ASVS checklist. Report only concrete, exploitable or requirement-violating issues with exact file and line. Don't report style issues.
3. Write `factory/stages/review.py`, run as `python -m factory.stages.review --base <sha> --head <sha> --out out/review`:
   - Build the diff with `git diff --unified=20 base...head`, capped in size. If it's over the cap, review the files most relevant to the threat model first, and note the truncation in the output.
   - Inputs: the diff, `security/threats.json` (if present), and the checklist for the ASVS level.
   - Run the adapter as a fresh session with read-only tools.
   - Post-process deterministically (hallucination guard): any finding whose `path` isn't in the diff, or whose lines fall outside the changed hunks plus context, is downgraded to `info` with a note. `confidence: low` findings are capped at `medium`.
   - Convert to factory findings (`source: ai-review`, stage `review`, tool `claude-code` or whichever adapter ran).
4. Add job `review` (`contents: read`):
   - Spec, change and fix modes: needs `codegen-commit`; base is the default branch, head is the pushed SHA.
   - Pull requests: base is `pull_request.base.sha`, head is `pull_request.head.sha`.
   - Pushes to the default branch: `before` to `after` (the full wiring for check mode is chunk 22).
   - Make the scanning jobs `needs: review`, so the review runs before the scanners as the design says.
5. Add `review` to the stage matrix (spec, change and fix modes here; check mode in chunk 22).
6. Tests, using the fake adapter: the hallucination guard (a path not in the diff gets downgraded); the confidence cap; diff truncation; schema validation.

## Outputs
`schemas/review.schema.json`, `prompts/security-review.md`, `factory/stages/review.py`, `tests/test_review.py`, fixtures, and updated `factory.yml` and `factory/stage_matrix.py`.

## Done when
- Selftest is green, including the guard tests.
- Re-run the notes-feature spec issue: the `review` job runs after `codegen-commit` and before the scanners (check the job timing in `gh run view`), and the gate report includes a "Review" section (empty is fine).
- Manually plant an obvious SQL string concatenation on a scratch `factory/` branch and re-run the review job by dispatching fix mode or re-running it. The review reports a `high` or `critical` finding, and the gate fails. Delete the scratch branch afterwards, after asking the owner.

## Size
M

## Dependencies
- Needs: 19.
- Parallel: none.

## Background

### From the design document
> "A second-agent security review: a separate Claude Code pass whose only job is to review the diff against the threat model and ASVS checklist, adversarially, before the scanners run."

> "The top row is the first build: a spec comes in, gets clarified and planned, threat modelled, and generated as code, then checked by a second-agent security review."

### Decisions that apply
- D5: the second-agent review is one of the four codegen layers.
- D19: high and critical review findings block the gate, and can be suppressed with a reason and expiry.
- D18: in check mode the review runs on PRs and default-branch pushes only (wired in chunk 22).

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
