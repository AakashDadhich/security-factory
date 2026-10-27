# 02. Pinned tool installer

## Goal
Every tool the factory uses gets onto a runner through one installer that reads exact versions and checksums from one lock file and refuses anything that doesn't match. Add workflow linting of the factory's own workflows.

## Inputs
- `plan/PROGRESS.md`
- From chunk 01: `factory/`, `Makefile`, `.github/workflows/selftest.yml`, `docs/runners.md`

## Tasks
1. Design `tools/versions.lock` as TOML (read with `tomllib`). Each entry has a `name`, `version` and `kind` (`binary`, `pipx`, `npm` or `container`). Binaries have per-platform `url`, `sha256`, `archive` (`tar.gz`, `zip` or `none`) and `bin` (path inside the archive), for `linux-x64` and `macos-arm64` where the tool runs there. A container has an `image` with an `@sha256:` digest.
2. Write `factory/tools.py` with `python -m factory.tools install <name> [<name>...]` and `python -m factory.tools list`:
   - `binary`: download over HTTPS to a temp dir, verify SHA-256 before extracting, install into `$HOME/.factory/bin`, and append that dir to `$GITHUB_PATH` when it's set.
   - `pipx`: `pipx install <name>==<version>`.
   - `npm`: `npm install -g <package>@<version>`.
   - `container`: `docker pull <image@digest>`.
   - Exit non-zero with a clear message on a checksum mismatch, an unknown tool or an unsupported platform.
3. Add first entries, using the latest stable releases and getting checksums from each project's published checksum files: `gitleaks` (binary, linux), `actionlint` (binary, linux), `zizmor` (pipx). Later chunks add their own entries.
4. Add `factory/platform_check.py` and a Make target `ensure-make` used on macOS jobs. If `make` is missing on `macos-15`, install it. If it's present, record the version in `docs/runners.md`.
5. Add the composite action `.github/actions/setup-factory/action.yml`. It assumes the factory repo is already checked out at `.factory/`. A workflow step does that first with `actions/checkout` (`repository: AakashDadhich/security-factory`, `ref: <factory-ref>`, `path: .factory`), then calls `uses: ./.factory/.github/actions/setup-factory`. A `uses:` ref can't be an expression, which is why it works this way. The action sets up Python 3.12, installs the factory package and its pinned requirements, and puts `$HOME/.factory/bin` on PATH. Every pipeline job will use it.
6. Unit tests (`tests/test_tools.py`): lock parsing, platform selection, checksum mismatch refusal (serve a fake file from a temp dir with a monkeypatched downloader), and the unknown-tool error.
7. Add a `lint-workflows` job to `selftest.yml` that installs actionlint and zizmor through the installer and runs both on `.github/workflows/` and `.github/actions/`. Fix anything they report.
8. Add a `macos-smoke` job to `selftest.yml` on `macos-15` that runs `python -m factory.tools list` and `make ensure-make`.

## Outputs
`tools/versions.lock`, `factory/tools.py`, `factory/platform_check.py`, `.github/actions/setup-factory/action.yml`, `tests/test_tools.py`, updated `selftest.yml`, `Makefile` and `docs/runners.md`.

## Done when
- The latest selftest run shows the `test`, `lint-workflows` and `macos-smoke` jobs all green (`gh run view <id>`).
- In the CI log, the pytest output includes a test that proves a wrong checksum is rejected.
- actionlint and zizmor report zero findings in the `lint-workflows` log.
- Every `kind = "binary"` entry in `tools/versions.lock` has a 64-character `sha256`, and every container image has an `@sha256:` digest.

## Size
M

## Dependencies
- Needs: 01.
- Parallel: 03, 05. Chunk 04 needs this chunk.

## Background

### From the design document
> "A hosted runner starts as a fresh, blank machine every time, so the workflow installs whatever it needs as its first steps. Nothing is installed on your own computer."

> "Others are installed by a setup step in the workflow, for example installing Semgrep with pip or downloading the Gitleaks and Syft binaries. This usually takes seconds."

> "Some tools run from a container image instead, which is the usual route for OWASP ZAP, since the image bundles everything it needs."

> "Pin exact versions of every tool, so a new release cannot quietly change what the gate catches. Because the setup lives in the factory repo's scripts, it is defined once and every project gets it."

> "Composite actions package individual stages, such as the SBOM step, as reusable building blocks."

### Decisions that apply
- D20: actionlint and zizmor, pinned, lint the factory's own workflows.
- D9: Gitleaks is installed as a binary, not through `gitleaks/gitleaks-action` (the binary needs no licence key or account).
- D13: Make with thin targets.
- Third-party actions are pinned by full commit SHA, never by tag. Tags can be moved, as happened in the 2025 `tj-actions/changed-files` compromise.

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
