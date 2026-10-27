# 27. Apple scripted checks

## Goal
Scripted versions of the manual Apple security review, run on every build. They check entitlements, hardened runtime, App Sandbox, App Transport Security, Keychain usage and privacy manifests, with macOS and iOS variants, and produce findings.

## Inputs
- `plan/PROGRESS.md`
- From chunk 26: the `apple-build` job and artifact (the zipped `.app`), `factory-test-macos`
- From chunk 03: `factory/findings.py`

## Tasks
1. Write `factory/apple/inspect.py`. The pure parsing functions use `plistlib`, so they're testable on Linux. Thin wrappers call `codesign -d --entitlements - --xml`, `codesign -dv --verbose=4` (for runtime flags) and `plutil` on macOS.
2. Write `factory/stages/apple_checks.py`, run as `python -m factory.stages.apple_checks --app <path.app> --platform <macos|ios> --src . --out out/apple-checks`. Rules, each with a rule id and severity:
   - macOS: hardened runtime flag missing (high); `com.apple.security.app-sandbox` missing or false (high).
   - Both platforms:
     - `get-task-allow` true in a Release build (high).
     - Risky entitlements, `cs.disable-library-validation`, `cs.allow-unsigned-executable-memory`, `cs.allow-dyld-environment-variables` (high), or any `temporary-exception` (medium).
   - ATS: `NSAllowsArbitraryLoads` true (high). `NSExceptionAllowsInsecureHTTPLoads` or `NSAllowsArbitraryLoadsInWebContent` (medium).
   - Privacy manifest:
     - `PrivacyInfo.xcprivacy` missing (high).
     - Invalid plist (high).
     - A required-reason API used in the source but not declared in `NSPrivacyAccessedAPITypes` (medium). Detect the API categories by source patterns: UserDefaults, file timestamp APIs, system boot time, disk space, active keyboards. Keep the pattern list in `factory/apple/required_reason_apis.yml`, citing Apple's documentation page.
   - Keychain: `kSecAttrAccessibleAlways` or `kSecAttrAccessibleAlwaysThisDeviceOnly` in the source (high). Secrets in UserDefaults are already covered by Semgrep rules, so don't duplicate them.
3. Run it inside `apple-build` after the build, on the same runner, and upload `out/apple-checks` as its own artifact `apple-checks`. Add it to the stage matrix for macOS and iOS.
4. Fixtures: entitlement XML files (good, sandbox missing, `get-task-allow`), Info.plist files (ATS on, arbitrary loads), and privacy manifests (valid, missing a declaration). Unit tests on Linux, plus a macOS integration test in selftest that builds nothing, runs `codesign` on a tiny ad-hoc signed binary created in the test, and asserts the parser reads its flags.

## Outputs
`factory/apple/__init__.py`, `factory/apple/inspect.py`, `factory/apple/required_reason_apis.yml`, `factory/stages/apple_checks.py`, `tests/test_apple_checks.py`, `tests/fixtures/apple/`, and updated `factory.yml`, `factory/stage_matrix.py` and `selftest.yml`.

## Done when
- Selftest is green on Linux (parsers) and macOS (the codesign integration).
- The latest `factory-test-macos` run has an `apple-checks` artifact with zero high findings, and the gate passes.
- Temporarily set `com.apple.security.app-sandbox` to false on a scratch branch: the gate fails with the sandbox rule. Revert afterwards.

## Size
M

## Dependencies
- Needs: 26.
- Parallel: 28.

## Background

### From the design document
> "Manual-style checks: entitlements, Keychain use, App Transport Security, sandboxing, hardened runtime and privacy manifests, scripted so they run on every build."

> "Platform extras: for iOS and macOS, rules covering Keychain use, App Transport Security, entitlements and sandboxing."

### Decisions that apply
- D12: MobSF static analysis for iOS (chunk 28), plus these scripted checks for both iOS and macOS. MobSF doesn't support macOS apps, so for macOS these checks are the whole of Apple "DAST".

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
