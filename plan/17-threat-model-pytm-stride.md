# 17. Threat model: pytm and STRIDE

## Goal
Build the threat model as code. The AI writes or updates a pytm model (`security/tm.py`) from the plan and the existing model, pytm runs it deterministically to produce the data-flow diagram and element list, and a second AI pass applies STRIDE to every element, producing `threats.json` with mitigations.

## Inputs
- `plan/PROGRESS.md`
- From chunk 16: the `plan` job and `out/plan/plan.json`, `schemas/plan.schema.json`
- From chunk 04: the adapter
- From chunk 15: `rules/asvs/asvs.json` (for mitigation ASVS refs)

## Tasks
1. Add lock entry `pytm` (`kind = "pipx"` or a pinned pip requirement in a separate venv, your choice; record it in `docs/runners.md`).
2. Write `schemas/threats.schema.json`:
   - `threats[]` with `id`, `framework` (`stride`, `linddun` or `attack-tree`), `category`, `element` (pytm element name), `title`, `description`, `likelihood` and `impact` (low/medium/high), `severity`, `mitigations[]` (`id`, `text`, `asvs_refs[]`), `status` (`open` or `mitigated`), `evidence` (optional path).
   - `model_version` (SHA-256 of `tm.py`).
   The `framework` field is there so chunk 18 can add LINDDUN and attack trees without a schema change.
3. Write `prompts/threat-model-pytm.md`. The input is `plan.json` plus the existing `security/tm.py` and `security/threats.json` if present. The output is JSON `{ "tm_py": "<python source>" }` (schema `schemas/tm-source.schema.json`). It must use only `pytm` imports and declare actors, servers/processes, datastores, dataflows and trust boundaries.
4. Write `factory/threatmodel/pytm_runner.py`:
   - Statically validate `tm_py` with the `ast` module. Allowed imports: only `pytm` and `sys`. No `open`, `exec`, `eval`, `__import__`, `subprocess` or `os`.
   - Write the source to `out/threat-model/tm.py`.
   - Run it in the job, which has no secrets beyond a read token, with a timeout, using pytm's `--dfd` (save the `.dot` file) and `--json` element export.
   - On a validation or run error, feed the error back to the adapter once.
5. Write `prompts/threat-model-stride.md`. The input is the pytm JSON elements and flows, plus the plan's abuse cases. For each element, ask the six STRIDE questions and return only applicable threats, each with mitigations mapped to ASVS ids.
6. Write `factory/stages/threat_model.py`, which runs task 4 and then task 5. In change mode it also passes the previous `threats.json`, keeps stable ids for unchanged threats, and marks removed ones. It writes `out/threat-model/{tm.py,dfd.dot,elements.json,threats.json}`.
   - Threat model output is not code findings. Additionally emit `findings.json` with one `info` finding per open threat (`source: ai-threat-model`), so the report shows them without blocking.
7. Add job `threat-model` (needs `plan`, `contents: read`), and add it to the stage matrix for spec and change modes.
8. Tests, using the fake adapter and fixture `tm_py` sources: an allowed model passes; `import os` is rejected; stable ids across an update; the info findings are emitted.

## Outputs
`schemas/threats.schema.json`, `schemas/tm-source.schema.json`, `prompts/threat-model-pytm.md`, `prompts/threat-model-stride.md`, `factory/threatmodel/__init__.py`, `factory/threatmodel/pytm_runner.py`, `factory/stages/threat_model.py`, `tests/test_threat_model.py`, fixtures, and updated `factory.yml`, `factory/stage_matrix.py` and `tools/versions.lock`.

## Done when
- Selftest is green, including the AST rejection tests.
- Re-label the notes-feature issue in `factory-test-web` (from chunk 16) with `factory:spec`. The `threat-model` job succeeds, and the artifact has `tm.py`, `dfd.dot` and a `threats.json` that validates, with at least one threat each for Spoofing, Tampering and Information disclosure, every threat carrying at least one mitigation with an ASVS ref.
- The job log shows the AST validation step passing before pytm runs.

## Size
L

## Dependencies
- Needs: 16.
- Parallel: none (18 and 19 build on it).

## Background

### From the design document
> "Threat model. The agent builds a data flow diagram from the spec, then asks structured questions of each element."

> "STRIDE: six questions per component (spoofing, tampering, repudiation, information disclosure, denial of service, elevation of privilege). Recommended default."

> "Tooling, all free: OWASP Threat Dragon for diagrams, or pytm to hold the model as code so it can be versioned and re-run on every change."

> "The factory reads the existing threat model and findings first, updates the threat model for what the change touches, and then runs a full security re-run of every stage, not a targeted one."

### Decisions that apply
- D3: STRIDE always. LINDDUN and attack trees are conditional (chunk 18).
- D4: pytm, so the model is code that can be versioned and re-run.
- D15: the model and threats are committed with the code under `security/` by the codegen stage (chunk 19). This stage only produces artifacts.
- Running AI-written Python is a risk: hence the AST allowlist, no secrets in the job, and a timeout.

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
