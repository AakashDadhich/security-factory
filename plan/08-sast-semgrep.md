# 08. SAST: Semgrep

## Goal
Run Semgrep Community Edition on every project with rule sets chosen by platform (TypeScript/JavaScript for web, Swift for Apple), plus factory custom rules, and emit findings.

## Inputs
- `plan/PROGRESS.md`
- From chunk 02: the installer and `tools/versions.lock`
- From chunk 03: `factory/sarif.py`
- From chunk 06: `factory.yml`, and `factory/config.py` (gives `platform`)

## Tasks
1. Add lock entries: `semgrep` (`kind = "pipx"`, exact version), and `semgrep-rules`, a new `kind = "git"` with repo `https://github.com/semgrep/semgrep-rules` and a full commit SHA. Teach the installer the `git` kind: a shallow fetch of that exact commit into `$HOME/.factory/semgrep-rules`. Don't copy the rules into the factory repo; they're under the Semgrep Rules License.
2. Write `factory/stages/sast_semgrep.py`, run as `python -m factory.stages.sast_semgrep --platform <p> --src . --out out/sast-semgrep`:
   - Rule sets per platform go in `semgrep-rules/rulesets.yml`. For `web`: the community `javascript/` and `typescript/` folders plus `semgrep-rules/custom/web/`. For `macos` and `ios`: the community `swift/` folder plus `semgrep-rules/custom/swift/`.
   - Run `semgrep scan --metrics=off --disable-version-check --sarif --output out/sast-semgrep/semgrep.sarif` with those configs.
   - Exclude `node_modules`, `dist`, `build`, `Pods`, `.build` and `.factory`.
   - Convert to findings (stage `sast-semgrep`, tool `semgrep`).
3. Write starter custom rules, each with a test file using Semgrep's `ruleid:` / `ok:` annotations:
   - Web (`custom/web/`): Express route without input validation reaching `res.send`; `child_process.exec` with request data; `jsonwebtoken` verify without an `algorithms` option; cookies set without `httpOnly`/`secure`.
   - Swift (`custom/swift/`): `UserDefaults` storing values named token, password or secret; `kSecAttrAccessibleAlways`; `CC_MD5`/`Insecure.MD5`/`Insecure.SHA1` used for security; `URLSession` delegate accepting all certificates.
4. Add job `sast-semgrep` to `factory.yml` (needs `setup`), and add it to the gate's needs.
5. In selftest, run `semgrep --test semgrep-rules/custom` and a unit test of the ruleset selection.

## Outputs
`factory/stages/sast_semgrep.py`, `semgrep-rules/rulesets.yml`, `semgrep-rules/custom/web/*.yaml` with tests, `semgrep-rules/custom/swift/*.yaml` with tests, `tests/test_sast_semgrep.py`, and updated `factory/tools.py`, `tools/versions.lock`, `factory.yml`, `selftest.yml` and `Makefile`.

## Done when
- The selftest log shows `semgrep --test` passing every custom rule test.
- The latest `factory-test-web` run has a green `sast-semgrep` job, and its artifact has `semgrep.sarif` and `findings.json`. The gate still passes, because the clean app has no high findings.
- The `sast-semgrep` job log shows `--metrics=off` and the pinned rules commit SHA.

## Size
M

## Dependencies
- Needs: 06.
- Parallel: 07, 09, 10, 12, 15.

## Background

### From the design document
> "SAST reads your source code without running it, looking for dangerous patterns such as SQL injection, hardcoded credentials or unsafe use of cryptography."

> "Semgrep Community Edition: fast, supports web languages and Swift, and lets you write custom rules. Recommended primary scanner."

> "Platform adapters. The core pipeline stays the same across projects. Only the scanning tools swap: web uses Semgrep or CodeQL plus OWASP ZAP for dynamic testing, while iOS and macOS use Semgrep with Swift rules plus MobSF and checks on entitlements, sandboxing and privacy manifests."

> "Most stages, such as Semgrep, Gitleaks and the SBOM, run fine on cheaper Linux runners, so only the Apple-specific stages need macOS at all."

### Decisions that apply
- D6: Semgrep CE is the primary scanner on all platforms. CodeQL, ESLint and SwiftLint are separate chunks (09, 26).
- Community Swift coverage is thin, which is why custom Swift rules exist. Expect to add more over time.
- The gate fails on any high or critical finding (chunk 11).

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
