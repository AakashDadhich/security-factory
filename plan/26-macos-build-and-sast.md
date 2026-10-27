# 26. macOS build and SAST

## Goal
Bring macOS apps into the factory. A small SwiftUI test app is built on a `macos-15` runner (ad-hoc signed, so entitlements are embedded), SwiftLint and CodeQL Swift run on macOS, and the existing Linux stages (Semgrep Swift rules, OSV-Scanner, Syft and Grype, Gitleaks) cover it.

## Inputs
- `plan/PROGRESS.md`
- From chunk 08: Semgrep with Swift rule sets selected by platform
- From chunk 10: `deps-sbom` (OSV-Scanner, Syft, Grype)
- From chunk 11: the gate and `factory/stage_matrix.py`
- From chunk 02: the installer (needs `macos-arm64` entries)

## Tasks
1. Ask the owner to create the public repo `AakashDadhich/factory-test-macos`, tag it with topic `security-factory`, add it to the App installation, and re-run the per-repo setup loop from `docs/setup-repos.md` (secrets, variables, secret scanning, push protection, Actions hardening).
2. Build the test app: a SwiftUI macOS app defined by an XcodeGen `project.yml`. Use one Swift Package dependency (any small, maintained package) so SwiftPM scanning has something to scan, and commit `Package.resolved`. Give it an entitlements file with App Sandbox on and hardened runtime enabled, a `PrivacyInfo.xcprivacy`, and `.factory.yml` with `platform: macos` and the `apple` keys. Add the stub.
3. Add lock entries: `xcodegen` (macos-arm64 binary with SHA-256), `swiftlint` (macOS portable binary with SHA-256), and an `xcode` entry naming the exact Xcode version to select (currently 16.4; check `docs/runners.md`).
4. Add job `apple-build` (`macos-15`, `contents: read`):
   - Run `sudo xcode-select -s /Applications/Xcode_<version>.app`, install xcodegen, and run `xcodegen generate`.
   - Build with `xcodebuild -scheme <scheme> -configuration Release CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual`.
   - Zip the `.app` with `ditto -c -k --keepParent`, and upload artifact `apple-build`.
5. Write `factory/stages/swiftlint.py` and add job `sast-swiftlint` on `macos-15`. It runs SwiftLint with the factory config `tools/swiftlint/.swiftlint.yml` (security-minded custom rules, such as a ban on `print` of variables named token or password, and `UserDefaults` with secret-like keys) and the SARIF reporter. Map severity: custom security rules = `high`, default rules = `low`.
6. Add job `sast-codeql-swift` on `macos-15` (`security-events: write`), with CodeQL `languages: swift` and `build-mode: manual`, using the same xcodebuild command. Convert the SARIF to findings.
7. Check that `deps-sbom` picks up `Package.resolved` for both OSV-Scanner and Syft. Fix the stage if it doesn't.
8. `factory/stage_matrix.py`: for `macos`, expect secrets, sast-semgrep, sast-swiftlint, sast-codeql-swift, deps-sbom and apple-build. Web-only jobs are `not-applicable`.
9. Tests: the SwiftLint severity mapping, the stage matrix for macOS, and the presence of the xcodebuild command builder flags.

## Outputs
In the factory: `factory/stages/swiftlint.py`, `tools/swiftlint/.swiftlint.yml`, `tests/test_swiftlint.py`, and updated `factory.yml`, `factory/stage_matrix.py`, `tools/versions.lock`, `docs/runners.md`. In `factory-test-macos`: the app, `project.yml`, entitlements, privacy manifest, `.factory.yml`, the stub.

## Done when
- The latest `factory-test-macos` run shows `apple-build`, `sast-swiftlint` and `sast-codeql-swift` on macOS, and `sast-semgrep`, `deps-sbom` and `secrets` on Linux, all green, with the gate passing.
- The `deps-sbom` artifact's `sbom.cdx.json` lists the Swift package.
- The `apple-build` artifact contains the zipped `.app`.
- Selftest is green.

## Size
L

## Dependencies
- Needs: 08, 10, 11.
- Parallel: 24, 25.

## Background

### From the design document
> "Platform adapters. The core pipeline stays the same across projects. Only the scanning tools swap: web uses Semgrep or CodeQL plus OWASP ZAP for dynamic testing, while iOS and macOS use Semgrep with Swift rules plus MobSF and checks on entitlements, sandboxing and privacy manifests."

> "SwiftLint with security-minded rules: a lightweight addition for iOS and macOS code."

> "Caveat: the Apple stages need macOS runners, which are free for public repos but billed at a higher rate for private ones, so keep that in mind for iOS and macOS projects."

> "On the free plan, up to 20 jobs can run at once across your account, and up to 5 of those can be macOS."

> "Full dynamic runs on Apple platforms need a bit more setup, so they come after the web adapter is working."

### Decisions that apply
- D6: Semgrep (Swift rules) + CodeQL Swift + SwiftLint for Apple.
- D7/D8: OSV-Scanner and Syft/Grype cover SwiftPM.
- P1: public repos, so macOS minutes are free. Keep macOS jobs to 3 per run to respect the 5-job macOS concurrency cap.
- SwiftLint isn't on the macOS runner image, and macOS runners have no Docker.

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
