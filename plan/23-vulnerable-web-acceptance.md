# 23. Vulnerable web app acceptance test

## Goal
Prove the whole web factory works. Run it against a deliberately vulnerable Express app with known planted flaws, and confirm automatically that each flaw is caught by the stage expected to catch it and that the gate blocks.

## Inputs
- `plan/PROGRESS.md` (owner, App name)
- The complete web pipeline from chunks 06 to 22: `factory.yml`, the gate, every stage
- The stub template `templates/project/.github/workflows/factory.yml`

## Tasks
1. Ask the owner to create the public repo `AakashDadhich/factory-vuln-web` (offer the `gh repo create` command), tag it with topic `security-factory`, and add it to the GitHub App installation. Then the owner re-runs the per-repo setup loop from `docs/setup-repos.md`, which sets its secrets and variables and turns on secret scanning, push protection and the Actions hardening. `acceptance.yml` runs in `security-factory`, so it mints its App token from the App secrets stored there.
2. Build the app (Express + TypeScript, with a Dockerfile and `openapi.yaml` like the clean test app). Add a README banner: "Intentionally vulnerable. Never deploy." Plant these flaws:
   - SQL injection: `better-sqlite3` query built with string concatenation from `req.query.id`.
   - Reflected XSS: `res.send('<h1>' + req.query.q + '</h1>')`.
   - Command injection: `child_process.exec('ping ' + req.query.host)`.
   - `eval` of request data.
   - A hardcoded fake API key in a generic pattern (`const apiKey = "<32 random hex chars>"`, made up and never a real provider format, so push protection allows it).
   - A committed `.env` file containing only fake values.
   - A known-vulnerable pinned dependency (for example `lodash@4.17.15`; confirm it has a high-severity advisory in OSV before using it).
   - No security headers (no helmet), and a session cookie without `HttpOnly` or `Secure`.
3. Write `expected-findings.yml` in that repo. Each entry has `id`, `stage`, a match (a `rule_id` regex or a `cwe`), `min_severity`, and `optional: true` for checks that depend on AI. For example: sqli by sast-codeql or sast-semgrep CWE-89 high; xss CWE-79; cmdi CWE-78; eval via sast-eslint; secret via secrets; `.env` via secrets `committed-env-file`; lodash via deps-sbom; headers via dast-web (low or medium, not blocking); review finding SQLi (optional).
4. Add the factory stub, in check mode only. Fix mode never runs here because nothing labels issues.
5. Write `factory/acceptance.py`, run as `python -m factory.acceptance --repo AakashDadhich/factory-vuln-web --run-id <id> --expected expected-findings.yml`. It downloads the `gate` artifact and asserts that the gate status is `fail` and that every non-optional expectation is matched. It prints a pass/fail table and exits non-zero on a mismatch.
6. Add `.github/workflows/acceptance.yml` in the factory (`workflow_dispatch`, plus weekly schedule):
   - Mint an App token for `factory-vuln-web`.
   - Trigger its stub with `workflow_dispatch`, wait for the run to complete (poll every 30 seconds, 60-minute timeout), and run the acceptance script.
   - Upload the table as an artifact.
   The App needs `actions: write` on that repo for the dispatch; ask the owner to add that permission to the App.
7. Tests: unit tests for the matcher (regex, CWE, severity floor, optional handling).

## Outputs
In the factory: `factory/acceptance.py`, `.github/workflows/acceptance.yml`, `tests/test_acceptance.py`. In `factory-vuln-web`: the app, `Dockerfile`, `openapi.yaml`, `.factory.yml`, `expected-findings.yml`, the stub, `README.md`.

## Done when
- `gh workflow run acceptance.yml --repo AakashDadhich/security-factory` completes green, which means the gate failed on the vulnerable app, as required.
- The acceptance artifact's table shows every non-optional expectation matched, with the stage that caught it.
- The `factory-vuln-web` run's gate summary lists the planted issues as blocking (critical/high).
- Record the result table in PROGRESS.md Notes (chunk 31 uses it).

## Size
M

## Dependencies
- Needs: 13, 21, 22.
- Parallel: none.

## Background

### From the design document
> "The gate. All findings from every stage are merged into one report. High-severity findings fail the build and loop back to code generation; a clean report ships the project and saves the threat model, SBOM and findings as its record."

> "Because tools overlap but also miss different things, running Semgrep and CodeQL together gives better coverage than either alone. The gate fails the build on any high-severity finding."

### Decisions that apply
- D6: Semgrep + CodeQL + ESLint security. D7: OSV-Scanner. D8: Syft + Grype. D9: Gitleaks. D11: ZAP baseline + active + OpenAPI.
- D10: push protection is on, so the planted secret must be a generic pattern, not a real provider format.
- D19: AI review findings block, but AI is non-deterministic, so expectations that depend on AI are optional.

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
