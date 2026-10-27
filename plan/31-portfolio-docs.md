# 31. Portfolio documentation

## Goal
Document the factory as a portfolio piece: what it is, how it works, what it caught, how the factory itself is secured, and its honest limits. Write it so the owner can lift it straight onto their portfolio website.

## Inputs
- `plan/PROGRESS.md` (the Notes hold acceptance result tables from chunks 23 and 29)
- `plan/decisions.md`, `plan/prerequisites.md`
- The factory repo as built: `docs/pipeline.md`, `docs/adapter.md`, `docs/contracts.md`, `docs/record.md`, `docs/runners.md`, `docs/release.md`
- The latest acceptance workflow run (`gh run list --workflow acceptance.yml`)

## Tasks
1. Write `docs/portfolio/case-study.md`, the main page (about 1,500 words, plain English, no em dashes). Sections: problem, approach, the pipeline, model portability, what it caught (acceptance tables with real numbers), securing the factory itself, cost (£0 beyond the existing Claude subscription), limits and next steps.
2. Diagrams in Mermaid, in `docs/portfolio/diagrams.md`:
   - the end-to-end flow, with the fix loop and the improvement loop,
   - the CI layout (project stub → reusable workflow → scripts → tools),
   - the model adapter (stages → adapter → model),
   - the per-mode job graphs.
3. Write `docs/portfolio/stages.md`, one short section per stage: purpose, tool, input, output, and what blocks the gate.
4. Write `docs/portfolio/factory-security.md`, covering how the factory protects itself:
   - least-privilege permissions per job,
   - SHA-pinned actions and the checksum-verified tool lock,
   - prompt-injection controls (read-only AI jobs, no App key, the AST allowlist for pytm, the patch path filter),
   - the actor allowlist,
   - credentials stored as per-repo secrets on a personal account (D21), applied and rotated by one setup loop,
   - no `pull_request_target`,
   - the throwaway internal Docker network for DAST,
   - fail-closed gate, and suppressions with expiry.
5. Write `docs/portfolio/samm.md`, a lightweight OWASP SAMM self-assessment of the factory (this was deferred here by D1). For each of the 5 business functions, give a maturity score of 0 to 3 per practice, the evidence (a link to the file or workflow), and one improvement.
6. Write `docs/portfolio/limits.md`, the honest gaps:
   - no iOS dynamic analysis (Corellium is paid), MobSF doesn't support macOS,
   - thin Semgrep Swift coverage,
   - AI non-determinism,
   - Pro usage limits,
   - no organisation, so secrets and Actions policy are copied per repo rather than defined once (D21); rotation means re-running the setup loop,
   - AI skipped on work-in-progress pushes (D18),
   - deferred items: Nuclei, TruffleHog, SOPS, Dagger, MCP, Ollama.
7. Update the factory `README.md` with a short summary, a status badge for selftest and acceptance, and links to the portfolio docs.

## Outputs
`docs/portfolio/{case-study,diagrams,stages,factory-security,samm,limits}.md`, and an updated `README.md`.

## Done when
- Every Mermaid block renders on GitHub (open each file in the GitHub web UI, or check with `gh api` markdown rendering).
- `grep -rn $'\xe2\x80\x94' docs/portfolio README.md` finds nothing.
- `case-study.md` contains the real acceptance numbers from PROGRESS.md Notes, and every claim links to a file or run.
- Every limit listed in task 6 appears in `limits.md`.

## Size
M

## Dependencies
- Needs: 00 to 30.
- Parallel: none.

## Background

### From the design document
> "The design principle is to keep the intelligence swappable and everything else deterministic. The orchestrator is plain code, not an AI: it decides which stage runs next, passes artifacts between stages and enforces the gate. The AI only appears inside specific stages, such as threat modelling, code generation and the security review, so the pipeline logic never depends on any one model."

> "OWASP SAMM: a maturity model, useful later for showing the factory itself follows good practice."

> "Caveat: for a private central repo to be callable from your other repos, sharing must be enabled in its settings, and on a free plan the simplest route is making the factory repo public, which suits a portfolio piece anyway."

> "Suggested approach. Build the Claude Code adapter first, keep prompts and rules as plain files from day one, and define the output formats before writing the stages. Adding a second model later is then a matter of writing one new adapter, and trying different models on the same project becomes easy whenever you fancy it."

### Decisions that apply
- D1: the SAMM self-assessment was deferred to this chunk.
- All decisions D1 to D20 and P1 to P8 are summarised for readers. Link to `plan/decisions.md` rather than copying it.
- Prices in GBP. The factory costs £0 beyond the existing Claude Pro subscription, because all repos are public.

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
