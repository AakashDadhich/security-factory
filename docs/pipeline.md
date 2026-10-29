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

## Spec and change modes

The project stub also triggers on `issues: [labeled]`. Label `factory:spec` runs mode `spec`, `factory:change` runs mode `change`; any other label skips the stub job. The stub passes the issue number as input `issue` and grants `issues: write`.

`authorize` is the first job in every run. In `spec` and `change` it runs `python3 -m factory.authorize --mode <m> --actor <sender> --allowed <list>` and fails unless `github.event.sender.login` is in the repo variable `FACTORY_ALLOWED_ACTORS` (comma-separated, case-insensitive; an empty list refuses everyone). Both values reach the script through `env:`. In other modes it passes without a check. `setup` needs `authorize`, and every other job needs `setup`, so a refused run calls no model. The gate is skipped after a refusal in spec or change mode; in any other mode it still runs with `if: always()` and fails closed.

### Plan stage

Job `plan` (spec and change modes, `contents: read`, `issues: read`) fetches the issue with `gh issue view --json title,body` into `out/plan/issue.json` and runs `python -m factory.stages.plan --issue-file out/plan/issue.json --config .factory.yml --out out/plan` (or `make plan ISSUE_FILE=...`). The stage calls the adapter with read-only tools, `prompts/plan.md` and a reply schema built from `schemas/plan.schema.json` without the derived fields, then sets them itself:

- `asvs_level`: the explicit `.factory.yml` value if set; otherwise 2, raised to 3 when `risk_rating` is `high` or `takes_payments` is true (D2),
- `personal_data`: `stores_personal_data`, or any `data_handled` entry classified `personal` or `sensitive`,
- `high_risk_features`: ids of features with risk `high`.

Feature and requirement ids must be unique and every feature needs at least one abuse case that names it; otherwise the stage exits 2. The artifact `plan` holds `plan.json`, an empty `findings.json`, `issue.json`, the raw `reply.json` and its `.meta.json`. Job `plan-comment` (`issues: write`, no AI) renders `plan.json` with `python -m factory.plan_comment` into a short Markdown comment and posts it with `gh issue comment`. Model text is escaped in the comment: Markdown punctuation is backslash-escaped, and `@` mentions and links are broken with a zero-width space. `plan` is a matrix stage for spec and change modes only.

## DAST web stage

Job `dast-web` (web only, required in the gate). `python -m factory.dast.harness up` creates the Docker network `factory-dast` with `--internal` (no route to the internet), builds the project's Dockerfile as `factory-app:<run id>`, and starts it detached with the alias `app`, `--read-only`, a tmpfs on `/tmp`, `--cap-drop ALL` and `no-new-privileges`. Only variables from `.env.example` are passed in. It then polls `http://app:<port><health_path>` from a pinned `curlimages/curl` container for up to 120 seconds and dumps the app logs on timeout.

`python -m factory.stages.dast_web --plan baseline` renders `zap/baseline.yaml` (target templated from `web.port`), runs the pinned ZAP image on the same network with `zap.sh -cmd -autorun`, and converts `zap-report.json` to findings (riskcode 3 high, 2 medium, 1 low, 0 info; CWE from `cweid`; fingerprint from plugin id, URL path and method). The artifact `dast-web` holds `findings.json`, `zap-report.json` and `zap-report.html`. `harness down` runs with `if: always()`.

## Workflow inputs

| Input | Default | Meaning |
|---|---|---|
| `mode` | `check` | `spec`, `check`, `fix` or `change` (`check`, `spec` and `change` exist so far) |
| `factory-ref` | `main` | Factory ref every job checks out into `.factory/` |
| `config-path` | `.factory.yml` | Project config file |
| `issue` | `0` | Issue number in spec and change modes, `0` otherwise |

Secret `CLAUDE_CODE_OAUTH_TOKEN` is optional. Without it, `hello-ai` is skipped and the gate still runs. Fork PRs never receive it.

## Project config

`python -m factory.config --path .factory.yml` validates the file against `schemas/factory-config.schema.json` and writes the GitHub outputs `platform`, `asvs_level` and `openapi`. A `null` or missing `asvs_level` becomes `2` (D2). `openapi` is empty when `web.openapi` isn't set. `platform: web` needs a `web` block; `macos` and `ios` need an `apple` block. Paths must be relative, inside the repo and on one line.

## Gate

`python -m factory.gate --artifacts in --config .factory.yml --manifest in/setup/run-manifest.json --out out/gate --needs "$NEEDS"`, where `NEEDS` is `toJSON(needs)` (optional; without it the gate judges stages by their artifacts alone).

- The stages it expects come from `factory/stage_matrix.py` for the manifest's platform and mode. Any other job in `needs` (for example `passthrough`, `hello-ai`) is checked too: a failure blocks, a skip does not. A matrix stage can only be skipped if its entry lists a skip reason (`fork-pr`, `not-applicable`).
- A missing, failed or invalid expected stage becomes a `critical` finding (`source: check`, rule `stage-missing` or `stage-failed`, location `stages/<name>`). These cannot be suppressed. An unusable run manifest also fails the gate.
- Findings with the same path, overlapping lines and a shared CWE merge into one (highest severity wins; `tools`, `stages`, `cwe` and `merged_fingerprints` list everything). Findings without lines only merge with other lineless ones.
- Policy: `policy.yml` in the factory sets `fail_on`. A project's `.factory.yml` can add `policy.fail_on_extra: [medium]` (medium, low or info only). The schema has no way to remove a level.
- Suppressions: `.factory.yml` `suppressions:` entries with `fingerprint`, `reason`, `expires` (ISO date, today to 90 days ahead) and `approved_by`. A suppression matches any fingerprint that was merged into a finding. Expired or malformed entries are ignored and reported as `medium` findings (`suppression-expired-N`, `suppression-invalid-N`). Suppressed findings stay in the report, marked `suppressed`.
- Outputs in `out/gate/`: `report.json`, `report.md` (also appended to `$GITHUB_STEP_SUMMARY`), `gate-result.json` (`status`, `counts`, `suppressed`, `blocking_fingerprints`, `mode`, `iteration`, `stages`, `reasons`) and `merged.sarif`. The job uploads the folder as artifact `gate` and the SARIF to code scanning with category `factory-gate` (the upload is allowed to fail, as fork PRs have no `security-events` write access).
- Exits 1 when `status` is `fail`.
