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

`authorize` is the first job in every run. In `spec` and `change` it runs `python3 -m factory.authorize --mode <m> --actor <sender> --allowed <list>` and fails unless both `github.event.sender.login` (who added the label) and `github.event.issue.user.login` (who wrote the issue) are in the repo variable `FACTORY_ALLOWED_ACTORS` (comma-separated, case-insensitive; an empty list refuses everyone). The author check matters because the issue body is fetched after the label is added, so an outside author could otherwise edit it in between. All values reach the script through `env:`. In other modes it passes without a check. `setup` needs `authorize`, and every other job needs `setup`, so a refused run calls no model. The gate is skipped after a refusal in spec or change mode; in any other mode it still runs with `if: always()` and fails closed.

### Plan stage

Job `plan` (spec and change modes, `contents: read`, `issues: read`) fetches the issue with `gh issue view --json title,body` into `out/plan/issue.json` and runs `python -m factory.stages.plan --issue-file out/plan/issue.json --config .factory.yml --out out/plan` (or `make plan ISSUE_FILE=...`). The stage calls the adapter with read-only tools, `prompts/plan.md` and a reply schema built from `schemas/plan.schema.json` without the derived fields, then sets them itself:

- `asvs_level`: the explicit `.factory.yml` value if set; otherwise 2, raised to 3 when `risk_rating` is `high` or `takes_payments` is true (D2),
- `personal_data`: `stores_personal_data`, or any `data_handled` entry classified `personal` or `sensitive`,
- `high_risk_features`: ids of features with risk `high`.

Feature and requirement ids must be unique and every feature needs at least one abuse case that names it; otherwise the stage exits 2. The artifact `plan` holds `plan.json`, an empty `findings.json`, `issue.json`, the raw `reply.json` and its `.meta.json`. Job `plan-comment` (`issues: write`, no AI) renders `plan.json` with `python -m factory.plan_comment` into a short Markdown comment and posts it with `gh issue comment`. Model text is escaped in the comment: Markdown punctuation is backslash-escaped, and `@` mentions and links are broken with a zero-width space. `plan` is a matrix stage for spec and change modes only.

### Threat model stage

Job `threat-model` (spec and change modes, needs `plan`, `contents: read`, no App key) checks out the project, installs claude-code and pytm, downloads artifact `plan` and runs `python -m factory.stages.threat_model --plan in/plan/plan.json --previous security --out out/threat-model` (or `make threat-model PLAN_FILE=...`). Up to four AI passes, all through the adapter with read-only tools (the first two always run):

1. **pytm model** (`prompts/threat-model-pytm.md`, reply `schemas/tm-source.schema.json`): input `plan.json` plus `security/tm.py` and `security/threats.json` when they exist. The reply's `tm_py` is checked with an AST allowlist (`factory/threatmodel/pytm_runner.py`): imports only `pytm` (not `sys`, so the model cannot change pytm's command line); from pytm only the model classes (never `Threat` or `Finding`, because pytm `eval()`s a threat's condition); no `open`, `exec`, `eval`, `compile`, `__import__`, `getattr`/`setattr`, `globals`/`vars`, `os`, `subprocess`; no `__` names except `__name__`; attributes only from an allowlist of pytm 1.4.0 element, data and control properties, enum members and `process` (a denylist missed paths like `gi_frame.f_globals`); no functions, classes, lambdas, loops, comprehensions, f-strings, `try`, `with` or non-integer subscripts; keyword arguments only from the same allowlist, with no `**` unpacking and never `threatsFile`, `condition`, `overrides`, `findings` or `sourceFiles`; no `report`, `load` or `loads`; and it must declare `TM`, `Boundary`, `Actor`, `Datastore`, `Dataflow`, a server or process, and call `tm.process()`. Only then is it written to `tm.py` and run through the fixed harness `factory/threatmodel/pytm_harness.py`, which loads the model without `__main__`, takes its one `TM` instance, resets `threatsFile` to pytm's bundled threat library and calls `process()` with the factory's own arguments. The harness runs in the pinned `pytm-sandbox` container (`python:3.12-slim` by digest) with `--network none`, `--read-only`, a small `noexec` tmpfs on `/tmp`, `--cap-drop ALL`, `no-new-privileges`, a 128 process and 1 GB memory cap, the job's uid, and no environment beyond `HOME=/work`. The output folder is the only writable mount (`/work`); the pytm venv's site-packages and the harness are mounted read-only, and the container's own process namespace keeps it away from the job's processes and their tokens. It runs with `-I` and a 120 s timeout (the container is removed on timeout), once with `--dfd` (saved as `dfd.dot`) and once with `--json` (`pytm.json`, normalised to `elements.json`: `boundaries`, `elements` with their class, `flows` with source and sink). Names must be unique and every flow must join known elements. On any validation or run error the stage asks the model once more (stage name `threat-model-pytm-retry`) with `tm.rejected.py` and `error.txt`; a second rejection exits 2.
2. **STRIDE** (`prompts/threat-model-stride.md`): input `elements.json`, `plan.json` and the previous `threats.json`. The reply schema is generated per run (`stride-reply.schema.json`): `element` must be a name from `elements.json`, `category` one of the six STRIDE categories, every threat needs at least one mitigation and every mitigation at least one ASVS id from `rules/asvs/asvs.json`. A `mitigated` threat needs `evidence`.

3. **LINDDUN** (`prompts/threat-model-linddun.md`), only when `plan.personal_data` is true. Same inputs and the same generated reply schema as STRIDE, with the seven categories `linking`, `identifying`, `non-repudiation`, `detecting`, `data-disclosure`, `unawareness`, `non-compliance`. Threats get `framework: linddun`.
4. **Attack trees** (`prompts/attack-tree.md`), once for each id in `plan.high_risk_features`. The stage writes `attack-trees/<feature_id>.feature.json` (the feature and its abuse cases) and a generated reply schema built from `schemas/attack-tree.schema.json`: the root `goal` must be one of that feature's abuse case `attacker_goal` values, leaf `element` a name from `elements.json`, ASVS ids from `rules/asvs/asvs.json`. A tree has at most 5 levels and 40 nodes (checked after validation; a breach fails the stage). `factory/threatmodel/attack_tree.py` flattens each leaf, in depth-first order, into a threat with `framework: attack-tree` and the feature id as `category`, and gives the leaf its `leaf_threat_id`. It writes `attack-trees/<feature_id>.json` (the numbered tree) and `attack-trees/<feature_id>.md`, a Mermaid flowchart (`and` as a hexagon, `or` as a rounded box, leaves with their threat id and severity, mitigations on dotted edges). Label text is escaped so it cannot close the diagram or the code fence.

The two conditional passes are deterministic: the triggers are plan fields, not model judgement. A pass that does not apply is skipped, and `passes.json` records every pass as `{"stride": {"status": "ran"}, "linddun": {"status": "ran"|"skipped", "reason": ...}, "attack-trees": {"status": "ran"|"skipped", "reason": ..., "features": [...]}}`. When a pass is skipped, threats of its framework from an earlier model move to `removed`. Stable ids work as for STRIDE, with attack tree leaves keyed by feature id, element and goal (or `previous_id` on the leaf). Adapter stage names: `threat-model-linddun`, `threat-model-attack-tree-<feature id lowercased, underscores as hyphens>`; fakes in `tests/fixtures/fake/`.

The factory then sets the rest: `framework` (`stride`, `linddun` or `attack-tree`); `severity` from likelihood times impact (9 critical, 6 high, 3 to 4 medium, else low); ids `TM-NNN` and mitigation ids `TM-NNN-Mn`. A threat keeps its previous id when its `previous_id` names a previous threat with the same category and element, or when category, element and normalised title match; otherwise it gets the next number, and numbers are never reused. Previous threats of a framework that are not matched move to `removed`. `model_version` is the SHA-256 of `tm.py`. Output in artifact `threat-model`: `tm.py`, `dfd.dot`, `pytm.json`, `elements.json`, `threats.json` (`schemas/threats.schema.json`), the replies with their `.meta.json`, and `findings.json` with one `info` finding per open threat (tool and stage `threat-model`, source `ai-threat-model`, rule id the threat id, location `security/threats.json`), so the report lists threats without blocking. `threat-model` is a matrix stage for spec and change modes only. This stage only produces artifacts; `codegen-ai` (see Code generation stages) commits `security/tm.py`, `security/threats.json` and the attack trees with the code.

## Code generation stages

Jobs `codegen-ai` and `codegen-commit` (spec and change modes; the matrix also lists fix mode for chunk 21) run after `threat-model`: `authorize → setup → plan → threat-model → codegen-ai → codegen-commit`. The security stages then check out the pushed commit (`needs.codegen-commit.outputs.sha`) and run on it, so a spec run scans the code it generated. In spec and change modes they wait for `codegen-commit` to succeed; in check mode they behave as before. `gate` also needs both jobs and checks out the same commit for the project config.

### codegen-ai

`contents: read`, the Claude token and no other credential; the job holds no write token. It installs claude-code, Semgrep with the community rules, Gitleaks and pre-commit (pinned in `tools/versions.lock`), downloads artifacts `plan` and `threat-model`, and runs `python -m factory.stages.codegen --plan in/plan/plan.json --threat-model in/threat-model --platform <p> --issue <n> --out out/codegen` (`make codegen`). The stage:

1. Checks out `factory/<issue>` (the remote branch if it exists, otherwise a new branch from the default branch) and records the commit as `base_sha`. The branch name is checked against `factory/<digits>`.
2. Writes the trusted files into the checkout: `CLAUDE.md` and `AGENTS.md` rendered with the platform, the plan's ASVS level and `threats.json` (`python -m factory.rules`), and `security/plan.json`, `security/tm.py`, `security/threats.json` and `security/attack-trees/<id>.md|json` copied from the artifacts.
3. Copies the tracked files and those trusted files into a temporary folder with **no `.git` folder** and runs the agent there through the adapter (`prompts/codegen.md`, reply `schemas/codegen-reply.schema.json`, tools Read, Grep, Glob, Edit, Write). The agent cannot run commands, so the generated code is never executed: nothing runs `npm`, the tests or the app in this job. The agent is told not to add dependencies because it cannot update a lock file. The copy has no git metadata so a write to `.git/config` or a hook cannot affect the git commands the job runs later, and symbolic links are refused.
4. Compares the copy with the baseline and applies only the differences to the real checkout, after a path check: not `.github/`, any `.env*` except `.env.example`, `.git`, scanner or hook configuration (`.semgrepignore`, `.gitleaksignore`, `.pre-commit-config.yaml`, `.npmrc` and similar), `CLAUDE.md`, `AGENTS.md`, `security/`, lock files; `package.json` dependencies and lifecycle scripts must not change; at most 300 files of at most 1 MiB. Files ignored by `.gitignore` are dropped. Changed files are staged by explicit path list, not the whole tree, because the job also holds `.factory/`, `in/` and `out/`.
5. Checks the staged patch (no symlinks or submodules, renames, binary content or `nosemgrep` and `gitleaks:allow` markers) and runs `pre-commit run` with the rendered `templates/precommit/.pre-commit-config.yaml`: only `repo: local` hooks calling the pinned `semgrep` (`--error --metrics=off --disable-nosem` and the platform's factory rule sets) and `gitleaks git --pre-commit --staged --redact=100` with `rules/gitleaks.toml`. The hooks get a minimal environment (no tokens).
6. A refusal (policy or hooks) goes back to the agent as `blocked-N.txt` and the agent runs again as adapter stage `codegen-fix-N`, at most 2 times. After that the stage exits 1 and `findings.json` holds one `high` finding with `source: check` and rule `precommit-blocked` or `patch-policy-blocked`.
7. Writes `changes.patch` (`git diff --binary --cached`) and `summary.json` (`branch`, `base_sha`, `files_changed`, `attempts`, `model`, `asvs_level`) and exposes `base_sha` as a job output. The artifact is `codegen-ai`.

### codegen-commit

No AI. It checks out `base_sha`, downloads `codegen-ai`, and in step `apply` (no token in the environment) re-checks the patch (same path rules, plus `--index` apply), re-runs pre-commit and commits as `aakashdadhich-factory-bot[bot]` with `feat: implement #<issue> (factory iteration <n>)` (iteration 0 until the fix loop). Only then does it mint an App token (`actions/create-github-app-token`, `contents: write`, this repo only) and push `HEAD:refs/heads/factory/<issue>` in a separate step. The push target must match `factory/<digits>` and never the default branch, the head must equal the recorded commit, and the push is never forced, so a branch that moved since `base_sha` is rejected. `FACTORY_APP_PRIVATE_KEY` is used only here and in `record`. A refused patch writes a `high` finding (`patch-refused` or `precommit-blocked`) and exits 1. Output: artifact `codegen-commit` (`commit.json`, `findings.json`, the rendered pre-commit config); the job output `sha` is the pushed commit.

The two code generation stages are matrix stages for spec, change and fix modes. Fix mode is not wired into the workflow yet (chunk 21).

## Security review stage

Job `review` is the second-agent review: a fresh adversarial Claude pass over the diff, before the scanners. `contents: read`, the Claude token and no other credential (no App key, no write token). `authorize → setup → plan → threat-model → codegen-ai → codegen-commit → review`, and then `secrets`, `sast-*`, `deps-sbom` and `dast-web` all `need` it, so the review finishes before any scanner starts. A failed review does not stop the scanners (the report stays complete), but the gate fails closed on a failed or missing `review` artifact.

When it runs:
- Spec and change modes, after `codegen-commit` succeeded: head is the pushed commit (`needs.codegen-commit.outputs.sha`), base is `origin/<default branch>`.
- Check mode on non-fork pull requests (`pull_request.base.sha` to `pull_request.head.sha`) and on pushes (`before` to the pushed commit; skipped when `before` is all zeros). These are not in the stage matrix yet, so they are not required; chunk 22 wires check mode fully.
- Fix mode is in the matrix for chunk 21 and is not wired into the workflow yet.

`python -m factory.stages.review --base <rev> --head <rev> --out out/review [--repo .] [--asvs-level 2] [--max-diff-bytes 200000]`:
1. Lists changed files with `git diff --name-only base...head` (never `security/`, which the factory generates) and takes each file's diff with `--unified=20`, parsing the hunks' new-side line ranges. Binary files have no hunks and are skipped.
2. Reads `security/threats.json` and `security/plan.json` at the head commit. Only `open` threats are passed on. The ASVS level is the plan's, else `--asvs-level` (the job passes the setup output), and `python -m factory.rules checklist` supplies the checklist.
3. Caps the diff at `--max-diff-bytes`. Files whose path or file name appears in an open threat come first, then files with more changed lines. A file that does not fit keeps the whole hunks that fit; what is left out is listed in `summary.json` and becomes one `info` check finding (`review-truncated`, source `check`, tool `factory`).
4. Runs the adapter (stage `review`, `prompts/security-review.md`, reply `schemas/review.schema.json`) with `Read,Grep,Glob` only. With no reviewable files the model is not called and the findings are empty.
5. Guards the reply deterministically. A finding whose `path` is not in the reviewed diff, or whose lines do not fit inside one reviewed hunk (changes plus their 20 lines of context), becomes `info` with a note. `confidence: low` caps the severity at `medium`. ASVS ids and threat ids that are not in the checklist or the open threats are dropped, with a note. Findings with the same path, start line and CWE collapse to the most severe.
6. Writes `findings.json` (stage `review`, source `ai-review`, tool = the adapter name with dashes, rule id `review-<first CWE>` or `review-general`), `summary.json`, `reply.json` and its meta, `diff.patch`, `checklist.json` and `threats.json`.

The gate report has a `### Review` section listing the unsuppressed findings from the `review` stage (`None.` when empty). High and critical review findings block like any scanner finding and can be suppressed by fingerprint with a reason and expiry. Exit codes follow the adapter (2 invalid reply, 75 usage limit).

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
