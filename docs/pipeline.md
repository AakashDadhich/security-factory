# Pipeline

A push to a project repo wakes its stub (`.github/workflows/factory.yml`, copied from `templates/project/`). The stub calls the reusable workflow `AakashDadhich/security-factory/.github/workflows/factory.yml@main` (D17: `@v1` once chunk 30 creates it) with `secrets: inherit` and grants it `contents: read`. A reusable workflow can't hold more permissions than its caller grants, so later chunks widen the stub when they need more.

Every job checks out the factory at `inputs.factory-ref` into `.factory/` and runs `./.factory/.github/actions/setup-factory`. Results travel between jobs only as artifacts, one per stage, named after the stage.

The project is checked out at the workspace root, so it is untrusted code sitting in the current directory. The workflow sets `PYTHONSAFEPATH=1` for every job so `python -m` never imports a project's own `factory/`, `yaml.py` or `pip/` instead of the factory's. The `setup` job reads the Claude token before it checks out the project.

## Current job graph (walking skeleton)

```mermaid
flowchart LR
    push([push / pull_request / workflow_dispatch]) --> stub[project stub]
    stub -->|workflow_call| setup
    setup -->|artifact: setup<br/>run-manifest.json| passthrough
    setup -->|has-claude == true| helloai[hello-ai]
    setup --> secrets
    setup --> gate
    passthrough -->|artifact: passthrough<br/>findings.json| gate
    helloai -->|artifact: hello-ai<br/>hello.json| gate
    secrets -->|artifact: secrets<br/>findings.json, gitleaks.sarif| gate
    gate{{gate<br/>if: always}}
```

| Job | Does | Artifact |
|---|---|---|
| `setup` | Checks out the project and the factory, validates the config with `python -m factory.config`, writes the run manifest with `python -m factory.manifest create`, checks whether `CLAUDE_CODE_OAUTH_TOKEN` is set | `setup` (`run-manifest.json`) |
| `passthrough` | Trivial stage: `python -m factory.passthrough` reads the manifest and writes an empty `findings.json` | `passthrough` |
| `hello-ai` | Only when the Claude token is present: installs claude-code and runs the hello prompt through `python -m factory.adapter`, then writes an empty `findings.json` | `hello-ai` (`hello.json`, `hello.json.meta.json`, `findings.json`) |
| `secrets` | Checks out the project with full history (`fetch-depth: 0`), installs the pinned Gitleaks and runs `python -m factory.stages.secrets`. See [Secrets stage](#secrets-stage) | `secrets` (`findings.json`, `gitleaks.sarif`) |
| `gate` | Always runs. Downloads every artifact into `in/<artifact>/` and runs `python -m factory.gate` | none |

## Secrets stage

`python -m factory.stages.secrets --repo . --out out/secrets` (or `make secrets`):

- runs `gitleaks git` over the whole history with `rules/gitleaks.toml` (Gitleaks defaults via `[extend] useDefault = true`), SARIF output to `out/secrets/gitleaks.sarif`, and `--redact=100` so the SARIF never holds a secret value,
- passes `--exit-code 99` because Gitleaks also exits 1 on its own errors. Exit 99 means leaks were found (findings, not a failure); any other non-zero exit fails the stage,
- turns every Gitleaks result into a `high` finding (D9: every committed secret counts, live or not), with CWE-798 and rotation advice,
- adds a `check` finding (`committed-env-file`, `high`, CWE-540) for each tracked file matching `(^|/)\.env(\.[^/]*)?$` except `.env.example` (D10),
- writes `out/secrets/findings.json`.

The same secret committed at the same path and line in several commits becomes one finding (the fingerprint ignores the commit).

## Workflow inputs

| Input | Default | Meaning |
|---|---|---|
| `mode` | `check` | `spec`, `check`, `fix` or `change` (only `check` exists so far) |
| `factory-ref` | `main` | Factory ref every job checks out into `.factory/` |
| `config-path` | `.factory.yml` | Project config file |

Secret `CLAUDE_CODE_OAUTH_TOKEN` is optional. Without it, `hello-ai` is skipped and the gate still runs. Fork PRs never receive it.

## Project config

`python -m factory.config --path .factory.yml` validates the file against `schemas/factory-config.schema.json` and writes the GitHub outputs `platform`, `asvs_level` and `openapi`. A `null` or missing `asvs_level` becomes `2` (D2). `openapi` is empty when `web.openapi` isn't set. `platform: web` needs a `web` block; `macos` and `ios` need an `apple` block. Paths must be relative, inside the repo and on one line.

## Gate (stub)

`python -m factory.gate --artifacts in --needs "$NEEDS" --optional hello-ai --optional sast-codeql --optional sast-eslint`, where `NEEDS` is `toJSON(needs)`:

- validates every `in/*/findings.json` against the findings schema,
- counts findings by severity and writes a Markdown table to `$GITHUB_STEP_SUMMARY` (and stdout),
- fails closed. It exits 1 if any finding is `critical` or `high`, any findings file is invalid, `--needs` is empty, any needed job ended with anything but `success` (a job named with `--optional` may also be `skipped`), or any successful job other than `setup` left no `findings.json`. Skipped optional jobs are listed under the tables so a skip is never silent.

Chunk 11 replaces this stub with the real gate and report.
