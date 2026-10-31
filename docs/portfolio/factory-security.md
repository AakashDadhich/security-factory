# How the factory protects itself

The factory holds a Claude token and a GitHub App key, runs untrusted generated code through scanners, and writes to other repositories. These are the controls, each with where to check it. Unit tests named below fail if the control is removed.

## Least-privilege permissions

[factory.yml](../../.github/workflows/factory.yml) starts with `permissions: {}` and every job grants itself only what it needs, usually `contents: read`. The write permissions are rare and listed per job: `issues: write` for the plan comment, `security-events: write` for SARIF upload, `contents: write` only through a short-lived App token. A reusable workflow cannot hold more than its caller grants, and `test_no_job_asks_for_a_permission_the_project_stub_does_not_grant` in [test_change_mode.py](../../tests/test_change_mode.py) stops the factory asking for more than the project stub allows.

## Pinned actions and a verified tool lock

Third-party actions are pinned by full commit SHA, and the repository's Actions allow list is set to GitHub-owned actions plus the factory's own workflows ([setup-repos.md](../setup-repos.md)). Tools are not downloaded ad hoc. [tools/versions.lock](../../tools/versions.lock) holds the exact version, URL and SHA-256 (or container digest) for each of 18 tools, and `python -m factory.tools install` refuses a mismatch ([test_tools.py](../../tests/test_tools.py)). Python packages for pytm install with hashes only. Dependabot proposes updates to action pins. The factory's own workflows are linted with actionlint and zizmor on every self-test run (D20).

## Prompt-injection controls

The model reads issue text, source code and diffs, all of which an attacker may influence. The controls assume the model can be tricked and limit what a tricked model can do:

- **Read-only AI jobs.** AI jobs get `contents: read` and the Claude token, never the GitHub App key. `test_app_private_key_only_reaches_codegen_commit_next_step_and_record` in [test_codegen.py](../../tests/test_codegen.py) fails if the key appears anywhere else.
- **A narrow tool list.** The adapter allows Read, Grep and Glob, plus Edit and Write only for code generation. `Bash`, `WebFetch` and `WebSearch` are always refused, so generated code is never executed in the AI job ([adapter.md](../adapter.md)).
- **No git metadata for the agent.** Code generation works in a copy without `.git`, so the agent cannot plant a hook or edit git configuration.
- **A path filter on patches.** [factory/patch_policy.py](../../factory/patch_policy.py) rejects changes to `.github/`, `.env*`, scanner and hook configuration, lock files, `CLAUDE.md`, `AGENTS.md` and `security/`, forbids dependency and lifecycle script changes, and refuses symlinks, submodules and suppression markers such as `nosemgrep`. A separate non-AI job re-checks and commits the patch.
- **Push target limited.** The bot can only push to `factory/<issue number>`, never forced and never to the default branch ([pipeline.md](../pipeline.md)).
- **An AST allowlist for pytm.** The AI writes a threat model as Python. [pytm_runner.py](../../factory/threatmodel/pytm_runner.py) accepts only a small set of imports, attributes and syntax, then runs it in a container with no network, a read-only filesystem and all capabilities dropped. Four bypasses found by automated review during development each became a test and a tighter allowlist.
- **Schema-checked replies.** Every AI reply must match a JSON schema, and derived fields such as the ASVS level are computed by code, not accepted from the model. The review stage downgrades findings that point outside the changed lines.

## The actor allowlist

Spec, change and fix runs spend allowance and write code, so `authorize` requires both the user who added the label and the issue author to be in `FACTORY_ALLOWED_ACTORS` ([authorize.py](../../factory/authorize.py)). The author check exists because an issue body is read after the label is added. `test_model_jobs_are_skipped_when_authorize_fails` in [test_plan_stage.py](../../tests/test_plan_stage.py) checks that no model job can run after a refusal.

## Credentials

There is no organisation, so no account-wide secrets (D21). Each repository that runs the factory holds its own `CLAUDE_CODE_OAUTH_TOKEN` and `FACTORY_APP_PRIVATE_KEY` as secrets and `FACTORY_APP_ID` and `FACTORY_ALLOWED_ACTORS` as variables. One loop in [docs/setup-repos.md](../setup-repos.md) applies the credentials and the same hardening to every repository tagged `security-factory`: a read-only default token, approval for fork PR workflows, secret scanning, push protection and the Actions allow list. Rotation is re-running that loop. The GitHub App is installed on selected repositories only. Nothing secret is committed; projects commit `.env.example` only, and the secrets stage flags a tracked `.env`.

## No pull_request_target

The stub triggers on plain `pull_request`. With a fork PR GitHub then sends no secrets and a read-only token. `pull_request_target` would run fork-influenced code with the base repository's secrets, so [test_eligibility.py](../../tests/test_eligibility.py) (`test_no_workflow_or_template_uses_pull_request_target`) fails if either workflows or templates use it. Fork PRs skip the AI stages and the record job.

## A throwaway internal network for DAST

The web app under test runs in a container on a Docker network created with `--internal`, with no route to the internet. ZAP joins the same network. [factory/dast/plan.py](../../factory/dast/plan.py) refuses any target other than `http://app:<port>` and any container command that is not on that network. The authenticated scan's test password is deleted from disk when ZAP exits.

## A fail-closed gate, and suppressions with expiry

The gate treats absence as failure. Only a `success` stage passes; a stage that is missing, failed, or skipped without a recognised reason becomes a critical `stage-missing` or `stage-failed` finding that cannot be suppressed ([gate section of pipeline.md](../pipeline.md)). Even the AI stages, which may be skipped on work-in-progress pushes, can be skipped only when the `ai-eligible` job recorded why. A usage-limit hit in check mode fails the stage rather than waving the commit through.

A project can suppress a finding in `.factory.yml`, but each entry needs a fingerprint, a reason, an approver and an expiry no more than 90 days ahead. Expired or malformed entries are ignored and reported as medium findings ([factory/gate.py](../../factory/gate.py)), and suppressed findings stay visible in the report.

## Releases

Projects follow the `v1` tag. The release workflow only moves it after finding a successful self-test and acceptance run on the exact commit, and the acceptance result must show both vulnerable apps checked out that commit ([release.md](../release.md)). Only the repository owner can run it.

## Known weak spots

These are accepted and written down rather than hidden. The project stubs pass `secrets: inherit` to the factory workflow, so every repository secret reaches it. The vulnerable acceptance targets call the workflow at `@main`. The reusable workflow YAML during acceptance comes from `main`, not from the candidate ref. More in [limits.md](limits.md).
