# 28. iOS build and MobSF

## Goal
Bring iOS apps into the factory. Build an unsigned device `.ipa` on macOS, run the iOS variant of the scripted checks, and run MobSF static analysis in Docker on Linux, producing findings.

## Inputs
- `plan/PROGRESS.md`
- From chunk 26: the `apple-build` job pattern, the xcodegen and xcode lock entries, the SwiftLint and CodeQL Swift jobs
- From chunk 27: `factory/stages/apple_checks.py` (iOS variant)
- From chunk 02: the installer (`container` kind)

## Tasks
1. Ask the owner to create the public repo `AakashDadhich/factory-test-ios`, tag it with topic `security-factory`, add it to the App installation, and re-run the per-repo setup loop from `docs/setup-repos.md` (secrets, variables, secret scanning, push protection, Actions hardening).
2. Build the test app: a minimal SwiftUI iOS app via XcodeGen. Use one Swift package, keep ATS default, store a sample value in the Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, and include `PrivacyInfo.xcprivacy`. Add `.factory.yml` with `platform: ios`, and the stub.
3. Extend `apple-build` for iOS:
   - Build with `xcodebuild -scheme <s> -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO`.
   - Package `Payload/<App>.app` into `app.ipa`, and upload artifact `apple-build`.
   - Run `apple_checks --platform ios`. With an unsigned build, read entitlements from the project's entitlements file instead of `codesign`.
4. Add lock entry `mobsf` (`kind = "container"`, `opensecurity/mobile-security-framework-mobsf`, pinned by digest).
5. Write `factory/stages/mobsf.py` and add job `mobsf` (`ubuntu-24.04`, needs `apple-build`, iOS only):
   - Generate a random API key for this run and pass it as `MOBSF_API_KEY`.
   - Start the container, wait for it to be ready, then use the REST API to upload the `.ipa`, scan it, and fetch the JSON report.
   - Map MobSF severities (`high` → high, `warning` → medium, `info` → info, `secure` → dropped) to findings with stage `mobsf`.
   - Stop the container.
6. Stage matrix: `ios` expects secrets, sast-semgrep, sast-swiftlint, sast-codeql-swift (with `-sdk iphoneos`), deps-sbom, apple-build, apple-checks and mobsf.
7. Tests: the MobSF report conversion (fixture JSON), the `.ipa` packaging helper, and the stage matrix for iOS.

## Outputs
In the factory: `factory/stages/mobsf.py`, `tests/test_mobsf.py`, `tests/fixtures/mobsf/`, and updated `factory.yml`, `factory/stage_matrix.py`, `tools/versions.lock`, `factory/stages/apple_checks.py`. In `factory-test-ios`: the app, `project.yml`, `.factory.yml`, the stub.

## Done when
- The latest `factory-test-ios` run shows `apple-build` (macOS) and `mobsf` (Linux) green, and its artifacts contain `app.ipa` and the MobSF `findings.json`. The gate passes, or any blocking MobSF findings on the clean app are triaged with suppressions that have reasons and expiry.
- Selftest is green.
- The `mobsf` job log never prints the API key value.

## Size
L

## Dependencies
- Needs: 26.
- Parallel: 27.

## Background

### From the design document
> "MobSF: free static and dynamic analysis for mobile and desktop binaries."

> "Full dynamic runs on Apple platforms need a bit more setup, so they come after the web adapter is working."

> "Most stages, such as Semgrep, Gitleaks and the SBOM, run fine on cheaper Linux runners, so only the Apple-specific stages need macOS at all."

### Decisions that apply
- D12: MobSF **static** analysis of the unsigned iOS `.ipa`, run in Docker on Linux. MobSF dynamic analysis for iOS needs Corellium, which is paid, so it isn't used. MobSF doesn't support macOS apps.
- macOS runners have no Docker. That's why MobSF runs on Linux and receives the `.ipa` as an artifact.
- No Apple Developer account is needed: the build is unsigned.

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
