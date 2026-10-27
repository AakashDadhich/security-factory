# 03. Data contracts

## Goal
Define the structured formats every stage exchanges, before any stage is written: the factory's finding schema, the run manifest, and helpers that turn SARIF and CycloneDX into the factory's formats.

## Inputs
- `plan/PROGRESS.md`
- From chunk 01: `factory/`, `schemas/`, `tests/`, `selftest.yml`

## Tasks
1. Write `schemas/finding.schema.json` (JSON Schema 2020-12) for one finding, and `schemas/findings.schema.json` for an array of them. Use exactly the fields in "Finding fields" under Factory facts below. `id` is `<stage>:<fingerprint>`. `fingerprint` is a SHA-256 of tool + rule_id + normalised location (path and line, or URL path and method).
2. Write `schemas/run-manifest.schema.json`: `run_id`, `mode` (`spec`, `check`, `fix` or `change`), `platform` (`web`, `macos` or `ios`), `iteration` (0 to 2), `issue` (nullable), `repo`, `commit_sha`, `factory_ref`, `asvs_level`, `stages` (name and status for each), `tool_versions` (map).
3. Write `factory/findings.py` with these functions: `load(path)`, `validate(list)`, `write(path, list)`, `fingerprint(...)`, and `make_finding(**fields)`, which fills in `id` and `fingerprint`.
4. Write `factory/sarif.py` with `sarif_to_findings(sarif_path, stage, tool)`. The severity map is: use the rule's `properties.security-severity` when present (>= 9.0 critical, >= 7.0 high, >= 4.0 medium, > 0 low). Otherwise use the SARIF `level` (`error` = high, `warning` = medium, `note` = low, `none` = info). Read CWE ids from rule tags such as `CWE-89` or `external/cwe/cwe-089`.
5. Write `factory/sbom.py` with `components(cyclonedx_path)` (name, version, purl) and `diff(old, new)` (added, removed, changed versions).
6. Write `docs/contracts.md`, a short description of each schema, the `out/<stage>/` convention, artifact naming, and the severity map.
7. Tests with small hand-written fixtures in `tests/fixtures/` covering: a Semgrep-style SARIF, a Gitleaks-style SARIF, a CodeQL-style SARIF with `security-severity`, and two CycloneDX files for the diff. Assert schema validity, the severity mapping, fingerprint stability, and the diff output.

## Outputs
`schemas/finding.schema.json`, `schemas/findings.schema.json`, `schemas/run-manifest.schema.json`, `factory/findings.py`, `factory/sarif.py`, `factory/sbom.py`, `docs/contracts.md`, `tests/test_findings.py`, `tests/test_sarif.py`, `tests/test_sbom.py`, `tests/fixtures/*`.

## Done when
- The selftest run is green, and the log shows the new tests passing.
- `python -m factory.sarif tests/fixtures/codeql.sarif --stage sast-codeql --tool codeql` (run in CI, or as a test) prints findings that validate against the schema, and a `security-severity` of 8.1 maps to `high`.
- Fingerprints for the same fixture are identical across two runs.

## Size
M

## Dependencies
- Needs: 01.
- Parallel: 02, 04, 05.

## Background

### From the design document
> "Each stage hands the next a predictable file, not free-form text. Findings go as JSON, scanner results as SARIF, and the SBOM as CycloneDX."

> "This means any stage can be replaced without breaking its neighbours, and the gate can read every result the same way, whichever model or tool produced it."

> "The AI stages are asked to reply in that agreed shape, and the adapter checks the reply fits before passing it on."

> "Suggested approach. Build the Claude Code adapter first, keep prompts and rules as plain files from day one, and define the output formats before writing the stages."

### Decisions that apply
- D8: the SBOM format is CycloneDX JSON only.
- D19: findings from the AI review use `source: ai-review` and are judged by the gate like any other finding.

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
