# 04. Model adapter

## Goal
One thin command that every AI stage calls. It takes a prompt file, input files and an output schema, runs the current model, and returns JSON that has been checked against the schema. Claude Code is the first adapter, and a fake adapter makes the stages testable without a model.

## Inputs
- `plan/PROGRESS.md`
- From chunk 01: the package layout. From chunk 02: `tools/versions.lock`, `factory/tools.py`, `.github/actions/setup-factory`.
- The repo secret `CLAUDE_CODE_OAUTH_TOKEN` in `security-factory` (set in chunk 00).

## Tasks
1. Add a `claude-code` entry to `tools/versions.lock` (`kind = "npm"`, package `@anthropic-ai/claude-code`, the current exact version).
2. Write the interface `factory/adapter/__init__.py`, used as:
   `python -m factory.adapter run --stage <name> --prompt prompts/<file>.md --input <path> [--input <path>...] --schema schemas/<file>.json --out out/<stage>/<file>.json [--workdir <dir>] [--allow-tools <list>] [--allow-write]`
   - It picks the adapter from env `FACTORY_MODEL_ADAPTER` (default `claude_code`).
   - It assembles the prompt from: the prompt file text, the input file paths and contents (within a size cap, larger files passed by path only), the JSON Schema, and a fixed instruction to reply with JSON only.
   - It validates the reply with `jsonschema`. If the reply is invalid, it retries once with the validation errors appended. If it's still invalid, it exits with code 2.
   - It writes the result to `--out` and a sidecar `--out.meta.json` (adapter, model, duration, attempts).
3. Write `factory/adapter/claude_code.py`. It runs the pinned `claude` CLI in headless print mode with JSON output, and checks the exact flag names against `claude --help` for the pinned version. Rules:
   - The tool allowlist is read-only by default (`Read`, `Grep`, `Glob`). Write and edit tools are added only with `--allow-write`. Web access is never allowed.
   - Auth comes only from env `CLAUDE_CODE_OAUTH_TOKEN`. The token is never logged.
   - The model id comes from env `FACTORY_CLAUDE_MODEL` (optional).
   - Recognise usage-limit or rate-limit errors and exit with code 75, printing "Claude usage limit reached; re-run later".
   - Enforce a timeout and a max-turns cap.
4. Write `factory/adapter/fake.py`, which returns canned JSON from the directory in `FACTORY_FAKE_RESPONSES` (`<stage>.json`) so stage tests run offline.
5. Add `prompts/hello.md` and `schemas/hello.schema.json` (`{"greeting": string, "model": string}`).
6. Add `.github/workflows/adapter-smoke.yml` in the factory repo, triggered by `workflow_dispatch` only. It runs on `ubuntu-24.04` with `contents: read`, uses `setup-factory`, runs `python -m factory.tools install claude-code` and the hello stage with the real adapter, passes `CLAUDE_CODE_OAUTH_TOKEN` through `env:`, and uploads `out/hello/`.
7. Tests (`tests/test_adapter.py`): prompt assembly, schema-failure retry, exit codes, usage-limit detection (with the CLI simulated by a stub script on PATH), and the fake adapter.
8. Write `docs/adapter.md`: the interface contract, how to add a second adapter, and the exit codes.

## Outputs
`factory/adapter/{__init__,__main__,claude_code,fake}.py`, `prompts/hello.md`, `schemas/hello.schema.json`, `.github/workflows/adapter-smoke.yml`, `tests/test_adapter.py`, `docs/adapter.md`, and an updated `tools/versions.lock`.

## Done when
- The selftest run is green, including the adapter tests.
- After the owner approves a push: `gh workflow run adapter-smoke.yml --repo AakashDadhich/security-factory` succeeds, and the `hello` artifact contains JSON that matches `schemas/hello.schema.json`.
- `grep -rn CLAUDE_CODE_OAUTH_TOKEN` across the run log shows no token value (GitHub masks it as `***`).
- Setting `FACTORY_MODEL_ADAPTER=fake` in a test produces the canned reply.

## Size
M

## Dependencies
- Needs: 01, 02.
- Parallel: 03, 05.

## Background

### From the design document
> "One small script that every AI stage calls. It takes a prompt file plus some input files, runs whichever model is current, and returns the result in the factory's standard format."

> "Models differ in how they are launched, how they are given access to files, and how their output is shaped. The adapter hides all of that, so those differences live in one place."

> "To change model, you rewrite only the adapter. The prompts, the stages and the orchestrator stay as they are."

> "Claude Code is the first adapter. A second one for another model can sit beside it, and a setting picks which one runs."

> "The AI stages are asked to reply in that agreed shape, and the adapter checks the reply fits before passing it on."

### Decisions that apply
- P2: Claude Pro. AI stages must fail cleanly and quickly on usage limits, never hang.
- D14: MCP and Ollama come later. Keep the adapter interface model-neutral so either can be added as another adapter.
- Prompt injection: AI stages read repo content that may be hostile, so the default tool allowlist is read-only, web access is never allowed, and the adapter never gets the GitHub App key.

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
