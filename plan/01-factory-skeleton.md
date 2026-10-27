# 01. Factory skeleton

## Goal
Lay out the factory repo, with a Python package, Make entry points and a self-test workflow on GitHub that runs pytest on every push. Record verified runner-image facts and concurrency limits.

## Inputs
- `plan/PROGRESS.md` (owner and repo names in Notes)
- Local repo `/Users/aakash/Documents/projects/secure-software-factory` (git initialised in chunk 00, contains `plan/`)

## Tasks
1. Create the layout: `factory/__init__.py`, `factory/__main__.py` (prints the factory version), `prompts/`, `rules/`, `schemas/`, `semgrep-rules/custom/`, `tools/`, `tests/`, `docs/`, `templates/project/`, `.github/workflows/`, `.github/actions/`. Put a `.gitkeep` in each empty folder.
2. Add `pyproject.toml` (name `security-factory`, `requires-python = ">=3.12"`, pytest config) and `requirements-dev.txt` with exact pins (pytest, jsonschema, PyYAML).
3. Add a `Makefile` with targets `test` (`python -m pytest -q`) and `help`. Keep targets thin.
4. Add `tests/test_smoke.py`, which checks that `python -m factory` prints a version.
5. Add `.github/workflows/selftest.yml`: runs on push and pull_request to `main`, `runs-on: ubuntu-24.04`, top-level `permissions: {}`, job permission `contents: read`. It uses `actions/checkout` and `actions/setup-python` pinned by full commit SHA (put the version in a trailing comment), installs `requirements-dev.txt`, and runs `make test`.
6. Add `.github/dependabot.yml` for the factory itself: ecosystems `github-actions` and `pip`, weekly.
7. Add `CLAUDE.md` for the factory repo: point to `plan/PROGRESS.md` and the session rules, and copy in the Factory facts below.
8. Add `README.md` (a short purpose statement and a link to `plan/00-index.md`) and `.gitignore` (Python, `out/`, `.venv/`, `.env`, `*.pem`).
9. Verify runner facts and write `docs/runners.md`. Fetch the current `actions/runner-images` readmes for `ubuntu-24.04` and `macos-15` (arm64), and record which of these are preinstalled, with versions: git, Python, Node, Docker, jq, yq, make, pipx, Xcode, SwiftLint, Homebrew. Fetch GitHub's current docs on Actions usage limits, and record the concurrent-job and macOS-job limits for the Free plan and the job and workflow time limits. Cite every URL and add the date.
10. Ask the owner, then push and confirm the self-test run is green.

## Outputs
`pyproject.toml`, `requirements-dev.txt`, `Makefile`, `factory/`, `tests/test_smoke.py`, `.github/workflows/selftest.yml`, `.github/dependabot.yml`, `CLAUDE.md`, `README.md`, `.gitignore`, `docs/runners.md`, plus the empty folders listed in task 1. All committed.

## Done when
- `gh run list --repo AakashDadhich/security-factory --workflow selftest.yml --limit 1` shows `completed success`.
- `gh run view <id> --log | grep passed` shows the smoke test passed.
- `grep -E 'uses: [^@]+@[0-9a-f]{40}' .github/workflows/selftest.yml` matches every `uses:` line (all pinned by SHA).
- `docs/runners.md` lists each tool with preinstalled yes/no, the concurrency limits, the time limits, source URLs and today's date.

## Size
M

## Dependencies
- Needs: 00.
- Parallel: none. 02, 03 and 05 can start after this.

## Background

### From the design document
> "Plain scripts and a Makefile that hold the real logic of each stage, so the pipeline does not depend on GitHub's workflow syntax. The workflow just calls them on the hosted runners."

> "Some tools come preinstalled on GitHub's runner images, such as git, Docker, Python and Node, and on the macOS images, Xcode."

> "Which tools are preinstalled changes over time, so the plan should check each one against GitHub's current runner image list rather than assuming."

> "On the free plan, up to 20 jobs can run at once across your account, and up to 5 of those can be macOS. Jobs above the cap queue until a slot frees up, and nothing fails."

### Decisions that apply
- P6: Python 3.12 and pytest. D13: Make with thin targets; Dagger later.
- Facts checked during planning on 2026-10-26 (re-verify them here): `ubuntu-24.04` has git, Python 3.12, Node 22, Docker, jq, yq, make, pipx, shellcheck, and the CodeQL bundle. `macos-15-arm64` has git, Python 3.14, Node 22, jq, Homebrew and Xcode 16.4 (26.x also installed), but **no Docker, and neither make nor SwiftLint is listed**.

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
