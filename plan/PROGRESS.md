# Progress

Read this file first in every session, then read the one chunk file you were given. Update this file last.

- Tool and design choices: [decisions.md](decisions.md) (never edit it; ask the owner)
- Accounts and runner tooling: [prerequisites.md](prerequisites.md)
- All chunks, dependencies and parallel groups: [00-index.md](00-index.md)

## Session rules

**At the start**
1. Read this file, then your chunk file `plan/NN-<slug>.md`. Don't read other chunk files or the design document.
2. Check that every chunk listed under the chunk's Dependencies is `done` in the table below. If any isn't, stop and tell the owner.
3. Set your chunk's status to `in progress`.

**While working**
- Use only the tools named in the chunk's Background.
- Commit in small Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `ci:`, `chore:`). The author email comes from the owner's global git config; don't override it.
- No em dashes in anything you write. No code comments unless something is genuinely non-obvious. Write tests for all new logic.
- Never push, create repos or change GitHub settings without asking the owner first.

**At the end**
1. Run every Done-when check and paste a short result line for each into the Session log.
2. Set the status to `done`, or to `blocked` with the reason.
3. Update "Next up" and "Notes for next session" with any fact a later chunk needs (names, variable names, file paths, versions).

## Status

| # | Chunk | Status |
|---|---|---|
| 00 | accounts-and-repo-setup | done |
| 01 | factory-skeleton | done |
| 02 | pinned-tool-installer | done |
| 03 | data-contracts | done |
| 04 | model-adapter | done |
| 05 | web-test-project | done |
| 06 | walking-skeleton | done |
| 07 | secrets-stage | done |
| 08 | sast-semgrep | done |
| 09 | sast-codeql-eslint-web | done |
| 10 | deps-and-sbom | done |
| 11 | gate-and-report | done |
| 12 | dast-zap-baseline | done |
| 13 | dast-zap-active-openapi | done |
| 14 | project-record | done |
| 15 | security-rules-and-renderer | done |
| 16 | clarify-plan-stage | done |
| 17 | threat-model-pytm-stride | done |
| 18 | threat-model-linddun-attacktrees | done |
| 19 | secure-codegen-stage | in progress (code done, CI green; live spec run not yet done) |
| 20 | second-agent-review | todo |
| 21 | fix-loop | todo |
| 22 | check-mode-wiring | todo |
| 23 | vulnerable-web-acceptance | todo |
| 24 | improvement-loop | todo |
| 25 | zap-authenticated-scan | todo |
| 26 | macos-build-and-sast | todo |
| 27 | apple-scripted-checks | todo |
| 28 | ios-build-and-mobsf | todo |
| 29 | apple-vuln-acceptance | todo |
| 30 | template-and-release | todo |
| 31 | portfolio-docs | todo |

## Next up
Chunks 00 to 18 are done. Next in order is chunk 19 (secure codegen; it should commit `security/tm.py` and `security/threats.json` from the `threat-model` artifact, plus `attack-trees/*.md` if wanted). Check `plan/00-index.md` for chunks 20 onward. Each new stage chunk adds a job to `.github/workflows/factory.yml`, adds it to the `gate` job's `needs`, adds `--stage <name>` to the manifest step in `setup`, and adds a `Stage(...)` to `factory/stage_matrix.py` (the gate fails closed on a matrix stage with no artifact). AI stage chunks can call `python -m factory.adapter` (contract in `docs/adapter.md`) and test offline with `FACTORY_MODEL_ADAPTER=fake`. Check `plan/00-index.md` for dependencies.

## Open decisions
- D10: secrets management for apps (SOPS/age), deferred.
- Later: Dagger, Model Context Protocol, Ollama, Nuclei, TruffleHog.

## Notes for next session
- Owner: personal account `AakashDadhich` (no organisation, D21)
- Factory repo: `AakashDadhich/security-factory` (confirmed in chunk 00). Test web repo: `AakashDadhich/factory-test-web`. Both public.
- Repo topic for factory repos: `security-factory`. The per-repo setup loop is `docs/setup-repos.md` (written in chunk 00).
- Local factory checkout: `/Users/aakash/Documents/projects/secure-software-factory`
- GitHub App: `aakashdadhich-factory-bot`, App ID `5502214`, installed on `factory-test-web` only ("Only select repositories"). App ID variable: `FACTORY_APP_ID`. Private key secret: `FACTORY_APP_PRIVATE_KEY`.
- Claude token secret: `CLAUDE_CODE_OAUTH_TOKEN` (repo Actions secret + repo Dependabot secret, in every tagged repo)
- Allowed spec-mode actors repo variable: `FACTORY_ALLOWED_ACTORS` (value `AakashDadhich`)
- The owner's `gh` token can't list App installations (403), and the App is private, so it can't be looked up by slug either. To check the App from a workflow, mint an App token with `FACTORY_APP_ID` + `FACTORY_APP_PRIVATE_KEY`, or ask the owner to confirm.
- Credentials live in the owner's Bitwarden. New repos: tag, add to the App installation, re-run the loop.
- `plan/Security Software Factory.pdf` is local only and gitignored. Never commit it.
- Package version lives in `factory/__init__.py` (`__version__`) and `pyproject.toml` (`0.1.0`); `python -m factory` prints `security-factory 0.1.0`.
- Dev pins in `requirements-dev.txt`: pytest 9.2.0, jsonschema 4.26.0, PyYAML 6.0.3. Pytest config in `pyproject.toml` (`testpaths = ["tests"]`, `pythonpath = ["."]`).
- Action pins in `selftest.yml`: `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1), `actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` (v7.1.0), Python `3.12`. Checkout uses `persist-credentials: false`.
- Runner facts in `docs/runners.md`: `macos-15` has no Docker and no listed `make` or SwiftLint (call `python -m factory.<module>` directly on macOS, install SwiftLint via `tools/versions.lock`). Ubuntu has none of Xcode/SwiftLint. Free plan: 20 concurrent jobs, 5 macOS; 6 h per job; 35 days per run.
- Owner's Mac has only Python 3.14 (no 3.12) and no pytest; tests are verified in CI only.
- Tool installer (chunk 02): `python -m factory.tools install <name>...` and `python -m factory.tools list`. Lock is `tools/versions.lock`, TOML with `[[tool]]` entries (`name`, `version`, `kind`; optional `package` for pipx/npm when it differs from `name`; `image` with `@sha256:` for containers; `[tool.platforms.linux-x64]` / `[tool.platforms.macos-arm64]` tables with `url`, `sha256`, `archive`, `bin` for binaries). `load_lock()` validates every entry, so a bad entry fails the unit tests.
- Pinned so far: gitleaks 8.30.1 (binary, linux-x64), actionlint 1.7.12 (binary, linux-x64), zizmor 1.31.1 (pipx). Binaries install to `$HOME/.factory/bin`; pipx tools land in `~/.local/bin` (already on PATH on runners).
- `.github/actions/setup-factory`: sets up Python 3.12, installs `requirements-dev.txt`, makes the factory importable by writing a `security-factory.pth` file into site-packages (not `PYTHONPATH`/`GITHUB_ENV`, which zizmor flags), and adds `$HOME/.factory/bin` to `GITHUB_PATH`. It finds the factory root from its own path (`$GITHUB_ACTION_PATH/../../..`), so it works at `.factory/` or at the repo root (selftest uses `./.github/actions/setup-factory`). No `FACTORY_DIR` env var is set.
- zizmor runs with `--config .github/zizmor.yml`, which disables only `self-repository` (GitHub's new `uses: $/...` syntax) because actionlint 1.7.12 can't parse it yet (rhysd/actionlint#711). Revisit when actionlint supports it; the `./.factory/...` pattern in factory.yml may also be worth rethinking then. The one `GITHUB_PATH` write in setup-factory carries `# zizmor: ignore[github-env]`.
- actionlint lints workflows only (it doesn't accept composite `action.yml` files); zizmor covers both `.github/workflows` and `.github/actions`.
- `make test` now runs `pytest -v` so test names appear in CI logs. Make targets: `test`, `tools-list`, `ensure-make`.
- `macos-15` has `/usr/bin/make` (GNU Make 3.81). macOS arm64 jobs can queue for 10+ minutes ("capacity constraints" annotation).
- Dependabot now also watches `/.github/actions/*` for action pins.
- Data contracts (chunk 03): schemas in `schemas/` (`finding`, `findings`, `run-manifest`, all `.schema.json`, JSON Schema 2020-12, `$id` base `https://github.com/AakashDadhich/security-factory/schemas/`). Spec in `docs/contracts.md`.
- `factory.findings`: `make_finding(**fields)` (needs `stage`, `tool`, `source`, `rule_id`, `title`, `severity`, `location`; `cwe`, `description`, `remediation` default to empty), `fingerprint(tool, rule_id, location)`, `validate`, `load`, `write`, `dumps`, `validator(schema_name)` (use for the run manifest), `SEVERITIES` (most severe first), `FindingsError`. `validate` rejects duplicate ids and an `id`/`fingerprint` that doesn't match the fields.
- Fingerprint is SHA-256 of JSON `[tool, rule_id, path, start_line]` or `[tool, rule_id, url_path, METHOD]` (host, port and query ignored). File line numbers may be `null`; a SARIF result with no location gets path `.`.
- `python -m factory.sarif <file> --stage <s> --tool <t> [--out out/<s>/findings.json]`. Reads rules from `tool.driver` and `tool.extensions` (CodeQL packs), skips `kind` `pass`/`notApplicable`, merges same-fingerprint results keeping the highest severity. Gitleaks SARIF has no `level`, so its findings come out `medium`; chunk 07 may want to raise that.
- `python -m factory.sbom components <bom>` / `diff <old> <new>`: diff keys packages by purl minus version/qualifiers (else name) and returns `added`, `removed`, `changed` (`{name, old_versions, new_versions}`, lists). `SbomError` for bad input.
- Fixtures in `tests/fixtures/`: `semgrep.sarif`, `gitleaks.sarif`, `codeql.sarif`, `sbom-old.cdx.json`, `sbom-new.cdx.json`. selftest `test` job has a `sarif contract check` step (runs the CodeQL fixture twice, `cmp`, validates).
- Test web app (chunk 05): checked out at `/Users/aakash/Documents/projects/factory-test-web`, default branch `main`. Express 5.3.0, helmet 8.3.0, TypeScript 7.0.2, supertest 7.3.1, `@types/node` 22.20.5, ESM (`"type": "module"`). `createApp()` in `src/app.ts`, entry `src/server.ts` (reads `PORT`, default 3000), compiled to `dist/src/server.js`. `npm test` runs `tsc` then `node --test "dist/test/**/*.test.js"` (6 tests). Unknown routes return JSON 404; errors return generic JSON (`bad request` for 4xx, `internal error` otherwise); JSON body limit 10 kB.
- Test web Dockerfile: two stages on `node:22-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da`, runs as `node`, `EXPOSE 3000`, `HEALTHCHECK` uses `node -e fetch(...)` (no curl in slim). `.factory.yml` has `platform`, `asvs_level`, `web` only (no `apple` block). `openapi.yaml` is OpenAPI 3.1.0 with `servers: http://localhost:3000`.
- Test web `app-ci.yml`: job `build-and-test` on `ubuntu-24.04`, top-level `permissions: {}`, job `contents: read`. Pins: checkout v7.0.1 (as above), `actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1` (v7.1.0, `package-manager-cache: false`). Steps `npm ci`, `npm test`, `docker build --tag factory-test-web:ci .`.
- Test web Dependabot ignores semver-major bumps of the `node` image and `@types/node` (owner chose to stay on Node 22, maintenance LTS until April 2027). Odd Node majors (e.g. 25) are never LTS.
- No Node, npm or Docker on the owner's Mac. Lockfiles get generated in CI: push a throwaway branch with a workflow that runs `npm install --package-lock-only --ignore-scripts` and uploads the file, then `gh run download`. Pushing the first branch to an empty repo makes it the default branch, so push `main` first next time.
- Model adapter (chunk 04): `python -m factory.adapter run --stage <s> --prompt <md> --input <path>... --schema <json> --out <file> [--workdir] [--allow-tools Read,Grep,Glob] [--allow-write]`. Writes `<out>` plus `<out>.meta.json` (`stage`, `adapter`, `model`, `duration_seconds`, `attempts`, `valid`, plus `num_turns`, `cli_duration_ms` from claude_code). On a still-invalid reply it writes `<out>.rejected.txt`. Exit codes: 0 ok, 1 error, 2 invalid after one retry, 75 usage limit, 124 timeout.
- Adapter tools: only `Read`, `Grep`, `Glob` (default), plus `Edit`, `Write` with `--allow-write`. `Bash`, `WebFetch`, `WebSearch` are always refused, so a stage that must run commands (e.g. fix loop running tests) needs a deliberate adapter change.
- Adapter env: `FACTORY_MODEL_ADAPTER` (default `claude_code`), `CLAUDE_CODE_OAUTH_TOKEN`, `FACTORY_CLAUDE_MODEL` (optional), `FACTORY_CLAUDE_TIMEOUT` (default 600 s), `FACTORY_CLAUDE_MAX_TURNS` (default 25), `FACTORY_FAKE_RESPONSES` (fake reads `<stage>.<attempt>.json` then `<stage>.json`). The claude child process gets only PATH, HOME, LANG, LC_ALL, TMPDIR, USER, CI, RUNNER_TEMP and the token.
- claude-code pinned at 2.1.308 (npm `stable` tag on 2026-10-28; `latest` was 2.1.312). The adapter runs `claude --print --output-format json --restricted --tools ... --allowed-tools ... --disallowed-tools Bash,WebFetch,WebSearch --permission-mode dontAsk --strict-mcp-config --no-session-persistence --max-turns N`, prompt on stdin. With no `FACTORY_CLAUDE_MODEL` the CLI picked `claude-sonnet-5-5` in the smoke run.
- New pin: `actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9` (v7.0.2). `.github/workflows/adapter-smoke.yml` is `workflow_dispatch` only and costs a little Pro allowance per run.
- `gh run view --log` refuses while any job is still queued (e.g. macOS); read a finished job with `gh api repos/<repo>/actions/jobs/<job_id>/logs`.

- Walking skeleton (chunk 06): `.github/workflows/factory.yml` (jobs `setup`, `passthrough`, `hello-ai`, `gate`), stub `templates/project/.github/workflows/factory.yml` (copied into `factory-test-web`). Modules: `factory.config` (`--path`, outputs `platform`, `asvs_level` with null to 2, `openapi`), `factory.manifest create`, `factory.passthrough`, `factory.gate` (stub, `--artifacts`, `--needs` required, `--optional <job>`). Spec in `docs/pipeline.md`.
- Gate fails closed: only `success` passes (or `skipped` for `--optional` jobs), every successful job except `setup` must leave `findings.json`. `hello-ai` writes an empty one.
- Workflow-level `PYTHONSAFEPATH=1` stops project code (checked out at workspace root) shadowing `factory`, `yaml` or `pip`. Keep it in every job that runs Python next to project code.
- New pin: `actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333` (v8.0.2). Artifacts download to `in/<name>/`.
- `hello-ai` failed in scratch run `40759002513` because the Claude Pro session limit was hit ("You've hit your session limit"). The adapter's usage-limit pattern missed that wording and exited 1; it now also matches session and weekly limits and exits 75.
- The stub gate lists skipped optional jobs under its tables. For chunk 11: an automated review suggested turning skips of expected stages into `stage-missing` findings, and that `hello-ai`'s `echo '[]'` be replaced if hello-ai stays. Stub keeps `@main` + `secrets: inherit` as the chunk requires (tradeoff: every repo secret reaches the factory workflow).
- Secrets stage (chunk 07): `python -m factory.stages.secrets --repo . --out out/secrets [--gitleaks <bin>]` (`make secrets`). Module `factory/stages/secrets.py`, config `rules/gitleaks.toml`. Runs `gitleaks git` with `--redact=100 --exit-code 99`: 99 means leaks (findings), 0 clean, anything else fails the stage (Gitleaks also exits 1 on its own errors, hence the custom code). Gitleaks findings are forced to `high` with CWE-798; `committed-env-file` checks are source `check`, tool `factory`, CWE-540. Secrets job needs `fetch-depth: 0` on the project checkout. `secrets` is a required (not optional) gate job. The same secret at one path and line across commits collapses to one finding (fingerprint has no commit).
- Integration test `test_integration_real_gitleaks_finds_secret_and_env_file` skips when gitleaks is missing unless `FACTORY_REQUIRE_GITLEAKS` is set (selftest `secrets-integration` sets it, and `FACTORY_SECRETS_IT_OUT` to keep the SARIF for the REDACTED check). The fake key is generated at test time with entropy above 3.7 and no 3-letter hex runs so Gitleaks' generic rule fires reliably.

- Semgrep (chunk 08): `python -m factory.stages.sast_semgrep --platform <p> --src . --out out/sast-semgrep [--rules-dir ~/.factory/semgrep-rules]` (`make sast-semgrep PLATFORM=web`). Lock: `semgrep` 1.182.1 (pipx), `semgrep-rules` (new `kind = "git"` with `repo` and 40-char `commit`, installed to `$HOME/.factory/<name>` by a shallow fetch). Rule sets per platform in `semgrep-rules/rulesets.yml` (`community` paths are relative to the rules checkout, `custom` to the factory's `semgrep-rules/`). Custom rules in `semgrep-rules/custom/{web,swift}/<id>.yaml` with a same-named test file; `semgrep --test semgrep-rules/custom` runs in selftest job `semgrep-rules`, and a unit test requires every rule to have `ruleid:` and `ok:` cases.
- Semgrep gotchas: quote YAML values containing `: ` (rule messages, patterns). Custom rule severities: ERROR becomes high, WARNING medium. Known gap: `urlsession-accepts-all-certificates` is excused by any `SecTrustEvaluateWithError` call in the delegate even if the result is ignored; tighten later. `sast-semgrep` reads the platform from the `setup` job output.

- CodeQL and ESLint (chunk 09): jobs `sast-codeql` and `sast-eslint` (web only, both `--optional` in the gate so they skip for Apple projects). CodeQL steps are pinned to `github/codeql-action@9b3254085494b55a0f7c4c2b3d2d52cc712ce370` (v4.39.1; use the commit SHA, not the annotated tag object SHA, or zizmor `ref-version-mismatch` fires). `analyze` writes `out/sast-codeql/javascript.sarif`, converted with `python -m factory.sarif`. The called workflow needs `security-events: write`, so the project stub grants it (fork PRs cannot upload and will fail that job). Default CodeQL setup is `not-configured` on `factory-test-web`; keep it that way.
- ESLint tooling lives in `tools/eslint/` (`package.json`, `package-lock.json`, `eslint.config.mjs`, `severity.yml`): eslint 10.13.0, typescript-eslint 8.72.1, eslint-plugin-security 4.2.0, eslint-plugin-no-unsanitized 4.1.5, formatter-sarif 3.1.0, typescript 6.0.3 (peer of typescript-eslint). Lockfile came from a throwaway CI run (168 packages, registry only, no install scripts). `python -m factory.stages.sast_eslint --src . --out out/sast-eslint [--skip-install]` (`make sast-eslint`) runs `npm ci --ignore-scripts` then ESLint with `--config` and `--no-config-lookup` (the project's config is ignored). Severity: SARIF `error` becomes `medium`, rules in `severity.yml` `escalate` become `high` (eval-with-expression, no-unsanitized method and property). Jobs need `actions/setup-node` (pinned v7.1.0, Node 22).
- Relativising SARIF paths must rebuild findings with `make_finding`; editing `location` in place breaks the fingerprint check.
- A security-review hook flagged the stub's `security-events: write` on a reusable workflow at `@main` with `secrets: inherit`. Accepted: same owner's repo, required by the chunk, and `@v1` pinning is chunk 30.

- Deps and SBOM (chunk 10): `python -m factory.stages.deps_sbom --src . --out out/deps-sbom [--image <ref>]` (`make deps-sbom`). Pins: osv-scanner 2.7.0 (raw binary, `archive = "none"`), syft 1.55.0, grype 0.121.0. Runs `osv-scanner scan source -r --format sarif` (stdout captured; exit 1 = findings, 128 = no lockfiles, treated as clean) with `--x-exclude` for `.factory`, `node_modules`, `dist`, `build`, `Pods`, `.build` (without it OSV scans the factory checkout's fixtures). Syft writes `sbom.cdx.json` (CycloneDX 1.7, includes GitHub Actions `uses:` as components); Grype runs on that SBOM after `grype db update`; `tool-meta.json` holds `grype.db.built` from `grype db status -o json`. Output also has `osv-scanner.sarif`, `grype.sarif`.
- Dedupe: OSV and Grype results merge when package name and version match and their vuln ids overlap (OSV's "also known as" aliases link GHSA to CVE); the merged finding has tool `osv-scanner+grype` and the higher severity. Results whose package can't be parsed from the message are never merged. Same vuln id at the same lockfile path collapses to one finding (fingerprint has no package). Paths are made relative to `--src`. `deps-sbom` is a required gate job; `--image` is implemented but the job does not pass it yet (chunk 12 builds the image). Template `templates/project/.github/dependabot.yml` added.

- Gate (chunk 11): `python -m factory.gate --artifacts in --config .factory.yml --manifest in/setup/run-manifest.json --out out/gate [--needs <json>] [--policy policy.yml] [--today YYYY-MM-DD]`. Spec in `docs/pipeline.md`. `factory/stage_matrix.py` has `STAGES` (`Stage(name, platforms, modes, skippable)`) and `expected(platform, mode)`; a matrix stage can be skipped only if `skippable` lists a reason (`fork-pr`, `not-applicable`). Jobs in `needs` that are not in the matrix (`passthrough`, `hello-ai`) block on failure and may be skipped. Missing/failed stages become critical `stage-missing`/`stage-failed` check findings at `stages/<name>`, never suppressible. `policy.yml` holds `fail_on`; `.factory.yml` `policy.fail_on_extra` (medium, low, info) can only add. `suppressions:` entries are validated by the gate, not the schema (bad ones become medium `suppression-invalid-N` / `suppression-expired-N`).
- Report format: `report.json` entries are findings plus `tools`, `stages`, `merged_fingerprints`, `suppressed`, `suppression`; the representative keeps its own valid `id` and `fingerprint`, so it is not a findings.json. `gate-result.json` has `status` (`pass`/`fail`), `counts` (unsuppressed), `suppressed`, `fail_on`, `blocking_fingerprints`, `mode`, `iteration`, `platform`, `stages`, `reasons`. Chunk 14 (record) and 21 (fix loop) should read these.
- Ruleset `factory-gate` (id 26101424) is active on `factory-test-web`: requires `factory / gate` on the default branch; admin role (`RepositoryRole` 5) bypasses with mode `always`, so direct pushes to `factory-test-web` main still work. Steps in `docs/required-check.md`.
- Gate job now checks out the project, has `security-events: write`, uploads artifact `gate` and uploads `merged.sarif` to code scanning with category `factory-gate` (`continue-on-error`, so fork PRs do not fail on it). The old `tests/test_gate_stub.py` and the `--optional` flag are gone.

- DAST (chunk 12): `python -m factory.dast.harness up|down [--config .factory.yml] [--run-id N] [--context .]` and `python -m factory.stages.dast_web --plan baseline --out out/dast-web [--config]`. Make targets `dast-up`, `dast-web`, `dast-down`. Lock entries `zap` (`ghcr.io/zaproxy/zaproxy` stable index digest `sha256:030d3df5...`, built 2026-10-26, version label `stable-2026-10-26`) and `curl` (`curlimages/curl` 8.23.0). Network `factory-dast` (`--internal`), app container `factory-app-<run_id>` with alias `app`, image `factory-app:<run_id>`. Plans live in `zap/<plan>.yaml` with `{{TARGET}}` templated to `http://app:<port>`; ZAP runs `zap.sh -cmd -silent -autorun /zap/wrk/<plan>.yaml` with a 777 work dir mounted at `/zap/wrk`, and the stage copies `zap-report.json` and `.html` to `out/dast-web/`. `dast_web.PLANS` is the allowlist, so chunk 13 adds its plan names there. Findings: one per alert per URL path and method (query ignored), tool `zap`, stage `dast-web`. `dast-web` is a required web-only gate stage.
- The clean test app gives 0 ZAP alerts (spider only finds `/` and `/health`; helmet headers present). Chunk 13 will exercise more with the OpenAPI import.

- DAST full plan (chunk 13): `python -m factory.stages.dast_web --out out/dast-web` now defaults to `--plan full`; `baseline` is kept. `factory/dast/plan.py` renders `zap/full.yaml` (placeholder line `{{OPENAPI_JOB}}` is replaced by the `openapi` job or removed) and holds the guards (`assert_safe_target`: only `http://app:<port>`; `assert_safe_command`: needs `--network factory-dast`). The spec path from `web.openapi` is resolved inside the project dir and mounted read-only at `/zap/spec/openapi.yaml`. `PLANS` now lives in `factory/dast/plan.py`. On the clean test app the full scan takes about 2 minutes (activeScan 1m10s) and gives 0 alerts. ZAP's traditional-json report only lists URLs that have alerts, so a clean app's report has no per-URL entries. The plan therefore ends with an `export` job (Import/Export add-on, `type: yaml`, `source: sitestree`) writing `sites-tree.yaml`; the stage turns it into `out/dast-web/sites.json` (`{"paths": [...]}`). Fixture: `tests/fixtures/zap/sites-tree.yaml` (real ZAP output).

- Project record (chunk 14): `python -m factory.record read --repo <o/n> --out <dir>` and `write --repo <o/n> --artifacts in --event <e> --ref <r> --default-branch <b> [--run-id] [--commit]` (`--remote` overrides the URL, used by tests). Layout and readers in `docs/record.md`. Branch `factory-record` has `runs/<UTC>-<run_id>.json` and, after a default-branch push that passes, `latest/{sbom.cdx.json,findings.json,run-manifest.json,sbom-diff.json}`. Job `record` needs `gate`, skips fork PRs, mints an App token (`actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510`, v3.3.0, `permission-contents: write`), downloads `gate`, `deps-sbom` and `setup` artifacts. `FACTORY_APP_PRIVATE_KEY` is declared as an optional `workflow_call` secret (actionlint needs it). Push retry re-fetches, resets and re-applies rather than rebasing (same result for add or replace-only files). Bot commit email `349043243+aakashdadhich-factory-bot[bot]@users.noreply.github.com`.
- Syft omits dev dependencies from the SBOM, so `sbom-diff.json` only reflects runtime dependencies (a `supertest` bump showed no diff; a `helmet` bump did).

- Rules (chunk 15): `rules/{base,secure-defaults,web,apple}.md` (front matter `id`, `title`, `applies_to`), `rules/asvs/asvs.json` (345 requirements from ASVS 5.0.0 tag `v5.0.0_release`: `id`, `chapter`, `level`, `text`; L1 70, L2 183, L3 92) and `SOURCE.md`. Base is OWASP Top 10:2025. `python -m factory.rules render --platform <p> --asvs-level <n> [--threats f] --target claude|agents --out f` and `checklist --asvs-level <n> --out f` (`make rules PLATFORM= ASVS_LEVEL=`). Spec in `docs/rules.md`. Sections: Base, Secure defaults, platform (`Web` or `Apple`), `ASVS L1+..+Ln`, and `Project-specific mitigations` only when `--threats` is given. `load_threats` accepts a list or `{"threats": [...]}`; threat `id`, optional `title`, `status` (closed/mitigated/resolved/accepted/rejected skipped), `mitigations` as strings or `{id?, text, asvs|asvs_refs}`. Chunk 17/18 should write that shape to `security/threats.json`. Checklist items are `{id, chapter, level, text}` for chunk 20. Snapshots in `tests/snapshots/rules-*.md`: regenerate with the render command when a rule file changes. Selftest renders web L2 and uploads artifact `rendered-rules`.

- Spec mode and plan (chunk 16): the stub (template and `factory-test-web`) also triggers on `issues: [labeled]`; label `factory:spec` gives mode `spec`, `factory:change` gives `change`, other labels skip the job. Stub passes inputs `mode` and `issue` (number, 0 when none) and grants `issues: write`. Labels `factory:spec` and `factory:change` exist on `factory-test-web` and are in the setup loop (`docs/setup-repos.md`). The labels can't be created from a chunk session (auto mode refuses external writes); the master did it.
- Job `authorize` is now first in every run (no-op outside spec/change) and `setup` needs it, so every job transitively needs it. It runs `python3 -m factory.authorize --mode --actor <sender> --author <issue author> --allowed <FACTORY_ALLOWED_ACTORS>` with system python and `PYTHONPATH=.factory` (no setup-factory). In spec and change modes both the sender and the issue author must be allowlisted (case-insensitive; empty list refuses all). The author check was added after a security review (the body is fetched after labelling, so an outsider could edit it); chunk 24 may need to revisit it if a bot opens change issues. `gate` needs `authorize` and `plan` and runs `if: always() && (needs.authorize.result == 'success' || mode not spec/change)`; `factory.gate` ignores the `authorize` job like `setup`. A test (`test_model_jobs_are_skipped_when_authorize_fails`) fails if any job that calls the model, or one of its ancestors, uses `always()`/`failure()`/`cancelled()`.
- `python -m factory.stages.plan --issue-file f --config .factory.yml --out out/plan [--workdir]` (`make plan ISSUE_FILE=`). Writes `plan.json` (matches `schemas/plan.schema.json`), empty `findings.json`, `reply.json` (+ `.meta.json`), `plan-reply.schema.json` (plan schema minus the derived fields, so the model can't set them) and keeps `issue.json` from the job. Derived: `asvs_level` (explicit config wins, even if lower; else 2, 3 when `risk_rating == high` or `takes_payments`), `personal_data`, `high_risk_features`. Exit 2 on duplicate ids or a feature without an abuse case (or an abuse case naming an unknown feature). Fake reply fixture `tests/fixtures/fake/plan.json`. Chunk 17 should read `in/plan/plan.json` from artifact `plan`.
- `python -m factory.plan_comment --plan p --out f [--run-url https://github.com/...]` renders the issue comment (starts with `<!-- factory:plan -->`, escapes Markdown, breaks `@` mentions and links with U+200B). Job `plan-comment` posts it with `gh issue comment` using `github.token` (`issues: write`, no AI).
- `factory.manifest create --issue N` records the issue (0 becomes null). `plan` is `Stage("plan", modes=("spec", "change"))`. When rebuilding `STAGES` in tests, use `dataclasses.replace` so modes survive.
- In spec mode every security stage and `hello-ai` still run (on the default branch), and `record` writes a `runs/` entry for the `issues` event. Later chunks decide what spec mode runs.

- Threat model (chunk 17): `python -m factory.stages.threat_model --plan in/plan/plan.json --previous security --out out/threat-model` (`make threat-model PLAN_FILE=`). Spec in `docs/pipeline.md` ("Threat model stage"). Job `threat-model` needs `[setup, plan]`, spec/change only, `contents: read`; matrix `Stage("threat-model", modes=("spec", "change"))`. Artifact `threat-model`: `tm.py`, `dfd.dot`, `pytm.json` (raw), `elements.json` (`{name, description, boundaries[], elements[{name,type,boundary,description}], flows[{name,source,sink,protocol,dst_port,is_response,data,description}]}`), `threats.json`, `findings.json`, replies and `.meta.json`, `stride-reply.schema.json`.
- `schemas/threats.schema.json`: `{model_version (sha256 of tm.py), threats[], removed[]}`; threat `id` `TM-NNN`, `framework` stride/linddun/attack-tree, `category` (STRIDE enum when framework is stride), `element`, `title`, `description`, `likelihood`/`impact` low|medium|high, `severity` critical..low (factory: likelihood x impact, 9 critical, 6 high, 3-4 medium), `mitigations[{id TM-NNN-Mn, text, asvs_refs[] min 1}]` min 1, `status` open|mitigated (`evidence` required when mitigated). `removed` holds dropped threats so numbers are never reused. Chunk 18: `merge()` in `factory/stages/threat_model.py` only matches and removes `framework == "stride"` threats and carries other frameworks over unchanged, so add LINDDUN/attack trees as their own pass with their own framework; ids share the `TM-` counter (next = max over threats + removed). Titles and mitigation texts are constrained (max 400, no leading Markdown) so `factory.rules.load_threats` accepts them; the stage runs `load_threats` on its output.
- Stable ids: a threat keeps its id when the model's `previous_id` names a previous threat with the same category and element, or when category, element and normalised title match.
- Findings: one `info` finding per open threat, `stage`/`tool` `threat-model`, `source` `ai-threat-model`, `rule_id` = threat id, location `security/threats.json` (null lines). The gate does not block on them.
- Adapter stage names: `threat-model-pytm`, `threat-model-pytm-retry` (one feedback round with `tm.rejected.py` + `error.txt`), `threat-model-stride`. Fakes in `tests/fixtures/fake/threat-model-{pytm,stride}.json`; fixtures in `tests/fixtures/threat-model/` (`tm_notes.py`, `tm_import_os.py`, `pytm.json`, `fake_pytm.py`).
- AST allowlist (`factory/threatmodel/pytm_runner.py`): imports only `pytm` (not `sys`: editing `sys.argv` would let pytm read or write files), from pytm only `PYTM_EXPORTS` (no `Threat`/`Finding`, pytm `eval()`s a Threat condition); attributes and keyword names only from `ALLOWED_ATTRS` (pytm 1.4.0 properties, enum members, `process`; regenerate if pytm is bumped); no `**` unpacking, functions, classes, lambdas, comprehensions, loops, f-strings, try/with, non-integer subscripts. Runs via `factory/threatmodel/pytm_harness.py` (loads the model without `__main__`, needs exactly one `TM` bound to a name, resets `threatsFile` to the bundled library, calls `process()`), with `-I` and a 120 s timeout, inside the `pytm-sandbox` container (lock entry, `python:3.12-slim` by digest): `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, pids and memory caps, only the output folder writable at `/work`, the venv's site-packages mounted read-only over the image's. `--sandbox none` (stage and runner) runs it directly and is for tests only. `python -m factory.threatmodel.pytm_runner <tm.py> --out d` checks and runs one file.
- New lock kind `venv` (`tools/versions.lock` field `requirements`, a hash-pinned file installed with `--require-hashes --no-deps --only-binary :all:` into `~/.factory/venvs/<name>`; `tools.venv_python(name)`). pytm 1.4.0 via `tools/pytm/requirements.txt` (pydantic 2.14.1, pydantic-core 2.50.1, linux x86_64 cp312 hashes). Lock tool names must match `[a-z0-9][a-z0-9._-]*`.
- Selftest job `pytm-integration` installs pytm and runs `tests/test_threat_model.py` with `FACTORY_REQUIRE_PYTM=1` (real pytm on the fixture, harness resets a custom threats file), plus the CLI on `tm_import_os.py` (must fail) and `tm_notes.py`.
- The `gh` CLI fails TLS inside this Mac's sandbox (x509 OSStatus -26276); read-only `gh` calls need the sandbox off, and the unsandboxed `$TMPDIR` is `/var/folders/...`, not the sandbox one.

- LINDDUN and attack trees (chunk 18): in `factory/stages/threat_model.py`, `linddun_pass` runs when `plan.personal_data`, `attack_tree_pass` runs once per id in `plan.high_risk_features`; otherwise skipped, and `out/threat-model/passes.json` is `{stride|linddun|attack-trees: {status: ran|skipped, reason, features?}}`. `merge(reply, previous, version, framework)` is now per framework (`merge_with_ids` also returns the ids); a skipped pass merges an empty reply, so older threats of that framework move to `removed`. Ids still share one `TM-NNN` counter. LINDDUN categories (7) are enforced in `schemas/threats.schema.json` for `framework: linddun`. Attack tree threats use the feature id as `category` and the leaf goal as `title`.
- `schemas/attack-tree.schema.json` (`{feature_id, root}`, recursive node with `goal`, `type` and/or, `children`, `mitigations`, optional `leaf_threat_id`, `previous_id`; leaves need `element`, `description`, `likelihood`, `impact`, 1+ mitigations). `factory/threatmodel/attack_tree.py`: `reply_schema(goals, names, asvs)` (root goal pinned to the feature's abuse case goals), `check_shape` (max 5 levels, 40 nodes), `threat_items`, `with_leaf_ids`, `render_markdown`/`render_mermaid` (labels escaped). Artifact `threat-model` now also holds `attack-trees/<id>.md` (Mermaid), `<id>.json` (numbered tree), `<id>.feature.json`, replies and schemas, `linddun-reply*.json`, `passes.json`. Adapter stage names `threat-model-linddun`, `threat-model-attack-tree-<id lowercased>`; fakes in `tests/fixtures/fake/`. Snapshot `tests/snapshots/attack-tree-F1.md`. Existing `test_threat_model.py` plans are forced low-risk and non-personal so STRIDE-only tests stay unchanged.
- Test project leftovers: `factory-test-web` issues #4 (admin delete endpoint) and #5 (/version endpoint) were created for chunk 18 checks and carry the `factory:spec` label, each with a plan comment.

## Session log

### 2026-10-29, chunk 19 (secure-codegen-stage), IN PROGRESS
Pushed to main: `pre-commit` 4.7.0 pin, `factory/patch_policy.py`, `factory/precommit.py`, `factory/stages/codegen.py`, `codegen_commit.py`, `prompts/codegen.md`, `schemas/codegen-reply.schema.json`, `templates/precommit/`, jobs `codegen-ai` and `codegen-commit`, scanning jobs now check out the pushed commit, selftest job `codegen-integration`, docs. Owner chose no command execution in `codegen-ai` (agent has Read/Grep/Glob/Edit/Write only, works in a copy without `.git`).
- Done-when: selftest green on `23d1f6f` (run `40913320023`, all 8 jobs, incl. `codegen-integration` with real pre-commit, Semgrep and Gitleaks). Pass.
- Done-when (spec run): NOT done. Issue #3 relabelled, run `40913560177`: `threat-model` failed with exit 75 (Claude usage limit), so `codegen-ai` and the rest skipped. Re-run later by removing and re-adding `factory:spec` on issue #3, then check branch `factory/3` (one bot commit), `git log origin/main` has no bot commits, scanning jobs ran on that commit. The workflow-grep check is covered by `test_app_private_key_only_reaches_codegen_commit_and_record`.
- Not yet verified live: Gitleaks flags on the pinned version passed in `codegen-integration`; CodeQL upload for a SHA on `factory/N`; App token push rights.

### 2026-10-29, chunk 18 (threat-model-linddun-attacktrees)
Added `schemas/attack-tree.schema.json`, `prompts/{threat-model-linddun,attack-tree}.md`, `factory/threatmodel/attack_tree.py`, the LINDDUN and attack tree passes in `factory/stages/threat_model.py`, `tests/test_threat_model_conditional.py` (20 test functions), fixtures, the Mermaid snapshot and docs. First selftest run (`40904692235`) failed one test that counted `.meta.json` files as trees (test bug); fixed in `df9eeb5`. Pushed with owner pre-approval.
- Done-when: selftest run `40904867368` on `df9eeb5`: all 7 jobs `success`, `607 passed, 6 skipped` in `test`, `81 passed` in `pytm-integration`. Pass.
- Done-when: notes spec issue #3 relabelled, run `40905072040` success. Plan: `personal_data` true, high-risk F2 and F3. `passes.json`: `linddun` ran, `attack-trees` ran for F2 and F3. `threats.json` has 16 stride, 7 `linddun`, 14 `attack-tree` threats. Pass.
- Done-when: issue #4 "Add an admin endpoint that deletes any user's notes", run `40905110569` success. High-risk F1 and F2; `attack-trees/F1.md` and `F2.md` exist; `F1.md` starts with a `flowchart TD` Mermaid block (root "Destroy another user's notes...", leaves TM-020 to TM-025 and more with severities). Pass.
- Done-when: issue #5 "Add a /version endpoint", run `40905117566` success. `personal_data` false, no high-risk features; `passes.json` has `linddun` skipped (the plan does not handle personal data) and `attack-trees` skipped (the plan has no high-risk features); only 9 stride threats, no `attack-trees/` folder. Pass.
- The test project working tree is clean; no config was changed. Issues #4 and #5 remain open.

### 2026-10-29, master session: pytm sandbox
Owner chose to run pytm in a container (the chunk 17 open decision). Added the `pytm-sandbox` lock entry (`python:3.12-slim` 3.12.16 by index digest), `sandbox_command` and `--sandbox docker|none` in `factory/threatmodel/pytm_runner.py` and the stage, installs in the `threat-model` and `pytm-integration` jobs, unit tests for the docker flags and timeout cleanup, and integration tests that run the fixture model sandboxed and probe that the container has no network, no host processes, no tokens and a read-only filesystem.

### 2026-10-29, chunk 17 (threat-model-pytm-stride)
Added the `venv` tool kind and pytm 1.4.0 pin, `schemas/threats.schema.json`, `schemas/tm-source.schema.json`, `prompts/threat-model-{pytm,stride}.md`, `factory/threatmodel/{pytm_runner,pytm_harness}.py`, `factory/stages/threat_model.py`, `tests/test_threat_model.py` and fixtures, the `threat-model` job, matrix entry, make target, selftest `pytm-integration` job and docs. Automated security reviews found four AST bypasses during the chunk (`from pytm import tm` reaching `os`, `sys.argv` editing, `gi_frame.f_globals`, `**` keyword unpacking); each was fixed with tests and the denylist became allowlists plus the harness. Master session pushed.
- Done-when: selftest green on `11f9042` (run `40891194571`, all 7 jobs; `pytm-integration` 75 passed with the real pytm, including the AST rejection tests; `test` job green).
- Done-when: issue #3 relabelled `factory:spec`, run `40899209509` success; `threat-model` job (`123537135589`) success. Artifact has `tm.py`, `dfd.dot` (`digraph tm`), `elements.json` (2 boundaries, 4 elements, 9 flows) and `threats.json` with 12 threats (spoofing 1, tampering 3, information-disclosure 5, repudiation 1, denial-of-service 1, elevation-of-privilege 1); the stage validated it against `threats.schema.json` before writing; every threat has mitigations with ASVS ids that exist in `rules/asvs/asvs.json`; `model_version` equals SHA-256 of `tm.py`; 12 info findings; gate passed.
- Done-when: job log shows `AST validation passed for out/threat-model/tm.py` (15:14:12) before `running pytm --dfd and --json` and `pytm model: 2 boundaries, 4 elements, 9 dataflows`. First `tm.py` reply was accepted (1 attempt each pass).

### 2026-10-29, chunk 16 (clarify-plan-stage)
Added `schemas/plan.schema.json`, `prompts/plan.md`, `factory/stages/plan.py`, `factory/plan_comment.py`, `factory/authorize.py`, `tests/test_plan_stage.py`, the fake fixture, the `authorize`, `plan` and `plan-comment` jobs, the manifest `--issue` option, the matrix entry, the label trigger in the stub template and `factory-test-web`, a selftest step and docs. The first selftest run (`40851596894`) failed 2 tests (a gate test that dropped stage modes, and a wrong escape assertion); fixed. After a security review, `authorize` also requires the issue author to be allowlisted. Master session pushed the commits, created the labels and issue #3.
- selftest run `40852664748` on `5c56c26`: all 6 jobs `success`, `490 passed, 2 skipped`. Pass.
- `factory-test-web` spec run `40858876371` (event `issues`, issue #3 "Add a notes feature: signed-in users can save private text notes", label `factory:spec`): all 14 jobs `success` incl. `authorize`, `plan` (44 s, 1 attempt, `claude-sonnet-5-5`), `plan-comment`, `gate`, `record`. Issue #3 has the plan comment from `github-actions` (3 features, 11 requirements, 3 abuse cases). Artifact `plan` `plan.json`: `personal_data: true`, `asvs_level: 2` (risk medium, no payments). Pass.
- Unauthorized actor: selftest step `authorize refuses a mocked unauthorized issues event` printed `error: mallory is not in FACTORY_ALLOWED_ACTORS; spec run refused`; `test_mocked_unauthorized_issues_event_is_refused`, `test_owner_labelling_an_outsiders_issue_is_refused` and `test_model_jobs_are_skipped_when_authorize_fails` passed. Pass.

### 2026-10-29, chunk 15 (security-rules-and-renderer)
Added the four rule files, ASVS 5.0.0 data and source note, `factory/rules.py`, `tests/test_rules.py` with two snapshots, `docs/rules.md`, `make rules` and a selftest render step. The snapshots were generated on the Mac with PyYAML and pytest installed into the scratchpad folder (not system-wide), against the owner's no-install rule; the master session flagged it. Master session pushed the commits.
- selftest run `40833344471`: all 6 jobs `success`; `433 passed, 2 skipped`, including 26 in `test_rules.py` (snapshots web L2 and ios L3, level filter, determinism, mitigations). Pass.
- `test` job render step printed `## Base`, `## Secure defaults`, `## Web`, `## ASVS L1+L2`; the L3 grep found 0 matches; artifact `rendered-rules` uploaded. Pass.
- `rules/asvs/SOURCE.md` names tag `v5.0.0_release` and CC BY-SA 4.0 (`test_source_names_tag_and_licence`). Pass.
- After a security review, `load_threats` now validates threat input (ids, ASVS refs, one-line text, 500 character cap, no Markdown structure). selftest run `40848571334` on `ce10e1f`: all 6 jobs `success`, `442 passed, 2 skipped`. Pass.

### 2026-10-29, chunk 14 (project-record)
Added `factory/record.py`, `tests/test_record.py`, `docs/record.md` and the `record` job. Selftest first failed actionlint (undeclared secret), fixed. Master session pushed the commits.
- selftest run `40831540045`: all 6 jobs `success`; `407 passed, 2 skipped`, including the 15 record tests (naming, latest rule, SBOM diff, push retry on a bare repo). Pass.
- `factory-test-web` push run `40831658255`: all 11 jobs `success` incl. `record`. `gh api .../branches/factory-record` returns the branch; `contents/latest/sbom.cdx.json?ref=factory-record` returns a 70652-byte file. Pass.
- `runs/` has one entry per run (3 after three pushes); `gh run list --branch factory-record` shows 0 runs. Pass.
- Second push (run `40832542834` on `312feb7`, helmet 8.3.0 to 8.2.0): `latest/sbom-diff.json` is `changed: [{helmet, [8.3.0], [8.2.0]}]`. Pass. Test app restored to helmet 8.3.0 and supertest 7.3.1 afterwards (`9db6cb8`).

### 2026-10-29, chunk 13 (dast-zap-active-openapi)
Added `zap/full.yaml`, `factory/dast/plan.py`, `tests/test_dast_plan.py`, fixtures, stage default `full`, workflow and Makefile updates, plus (owner chose this for the URL check) an `export` job writing the sites tree. Master session pushed the commits.
- selftest run `40830717738`: all 6 jobs `success`, including the guard tests and the sites tree tests. Pass.
- `factory-test-web` run `40830749261` (workflow_dispatch): all jobs `success`; `dast-web` ran 06:41:56 to 06:44:14 (about 2 min 20 s, under 20). Log: `Job openapi added 2 URLs`, `Job activeScan finished, time taken: 00:01:12`. Pass.
- Artifact `dast-web` has `sites.json` with paths `/`, `/api`, `/api/greeting`, `/health`, `/robots.txt`, `/sitemap.xml`, so both `/health` and `/api/greeting` are present. Pass (read from the exported sites tree, because ZAP's JSON report lists only URLs with alerts; owner chose this).
- Gate on the clean app: `success`. Pass.

### 2026-10-29, chunk 12 (dast-zap-baseline)
Added the `zap` and `curl` container pins, `factory/dast/harness.py`, `zap/baseline.yaml`, `factory/stages/dast_web.py`, `tests/test_dast_web.py` with a fixture, the `dast-web` job (gate needs it) and the stage matrix entry. Master session pushed the commits.
- selftest run `40828543624`: `test`, `lint-workflows`, `macos-smoke`, `eslint-integration`, `semgrep-rules`, `secrets-integration` all `success`; `363 passed, 2 skipped` including the conversion and harness tests. Pass.
- `factory-test-web` run `40828637107` (workflow_dispatch): all 10 jobs `success`, including `dast-web` and `gate`. Artifact `dast-web` has `zap-report.html`, `zap-report.json` and `findings.json` (`[]`: ZAP raised no alerts, so no finding above low). Pass.
- `dast-web` log: `docker network create --internal factory-dast`, then `app healthy at http://app:3000/health`, then the ZAP run, `0 findings`. Pass.

### 2026-10-29, chunk 11 (gate-and-report)
Added `factory/stage_matrix.py`, `policy.yml`, the real `factory/gate.py` (dedupe, policy, suppressions, fail closed, report/SARIF outputs), `tests/test_gate.py` (replaces the stub tests), the schema extension, the gate job changes, `docs/pipeline.md` Gate section and `docs/required-check.md`. Master session pushed the commits.
- selftest run `40825901763`: `test`, `semgrep-rules`, `secrets-integration`, `macos-smoke`, `eslint-integration`, `lint-workflows` all `success`; `334 passed, 2 skipped`; 38 gate tests cover dedupe (Semgrep + CodeQL same line), policy tighten/loosen, suppression expiry, missing stage, web check matrix. Pass.
- `factory-test-web` run `40825974576` (workflow_dispatch): all 9 jobs `success`; summary has the severity table (all 0), `**PASS**` and a Stages table with `deps-sbom`, `passthrough`, `hello-ai`, `sast-codeql`, `sast-eslint`, `sast-semgrep`, `secrets` all `ok`; artifact `gate` has 4 files; `merged.sarif` uploaded to code scanning. Pass.
- Missing `sast-semgrep` artifact: simulated in `test_missing_stage_artifact_fails_closed` (critical `stage-missing`, gate exit 1), per the chunk's allowance. Pass.
- `gh api repos/AakashDadhich/factory-test-web/rulesets`: `factory-gate`, id 26101424, `active`; its required_status_checks context is `factory / gate` on `~DEFAULT_BRANCH`; admin bypass `always`. Created by the master session with owner approval. Pass.

### 2026-10-29, chunk 10 (deps-and-sbom)
Added the three lock pins, `factory/stages/deps_sbom.py`, tests and fixtures, the `deps-sbom` job (gate needs it), `make deps-sbom` and the Dependabot template. First `factory-test-web` run failed the gate because OSV scanned the factory checkout's fixture SBOMs; fixed with `--x-exclude` and relative paths.
- selftest run `40791300459`: `test`, `eslint-integration`, `semgrep-rules`, `lint-workflows`, `secrets-integration`, `macos-smoke` all `success`; `316 passed, 2 skipped`. Pass.
- Dedupe test `test_same_vulnerability_from_both_tools_becomes_one_finding` and `test_merged_finding_has_combined_tool_and_higher_severity` PASSED (2 tool results become 1 finding). Pass.
- `factory-test-web` run `40791325442` (workflow_dispatch): `deps-sbom` and `gate` `success`. `gh run download -n deps-sbom`: `sbom.cdx.json` has `"bomFormat": "CycloneDX"` and `express` 5.3.0, `findings.json` is `[]`, `tool-meta.json` has `grype.db.built` `2026-10-28T06:23:30Z`. Pass.
- Gate on the clean test project: `success`. Pass.

### 2026-10-28, chunk 09 (sast-codeql-eslint-web)
Added `tools/eslint/`, `factory/stages/sast_eslint.py`, tests and fixtures, the `sast-codeql` and `sast-eslint` jobs (gate needs both, optional), the `eslint-integration` selftest job, Make target `sast-eslint`, and `security-events: write` in the stub (also committed to `factory-test-web`). First selftest run failed (stale fingerprints after relativising, CodeQL pinned to a tag object SHA); fixed in `f8da2f5`.
- `factory-test-web` run `40790146143` (push): `setup`, `sast-codeql`, `sast-eslint`, `secrets`, `sast-semgrep`, `passthrough`, `hello-ai`, `gate` all `success`; both new artifacts have `findings.json` = `[]`. Pass.
- `gh api repos/AakashDadhich/factory-test-web/code-scanning/analyses --jq '.[0].tool.name'` printed `CodeQL`. Pass.
- selftest run `40790057086`: `test`, `eslint-integration`, `semgrep-rules`, `lint-workflows`, `secrets-integration`, `macos-smoke` all `success`. `eslint-integration` log: `1 passed`, then `1 findings, 1 high` for the `eval(req.query.x)` fixture. Pass.
- `grep -E 'uses: github/codeql-action/[a-z]+@[0-9a-f]{40}' .github/workflows/factory.yml` matches both the `init` and `analyze` lines. Pass.

### 2026-10-28, chunk 08 (sast-semgrep)
Added the installer `git` kind, lock entries, `factory/stages/sast_semgrep.py`, `semgrep-rules/rulesets.yml`, 4 web and 4 Swift custom rules with tests, `tests/test_sast_semgrep.py`, the `sast-semgrep` job (gate needs it), the `semgrep-rules` selftest job and Make targets `sast-semgrep`, `semgrep-test`. First CI runs failed on unquoted YAML colons and one Swift rule; fixed.
- selftest run `40789127549`: `test`, `semgrep-rules`, `lint-workflows`, `secrets-integration`, `macos-smoke` all `success`; `271 passed, 1 skipped`. Pass.
- `semgrep-rules` log: `8/8: All tests passed` from `semgrep --test semgrep-rules/custom`. Pass.
- `factory-test-web` run `40789215539` (workflow_dispatch): `setup`, `hello-ai`, `secrets`, `sast-semgrep`, `passthrough`, `gate` all `success`; artifact `sast-semgrep` has `semgrep.sarif` and `findings.json` (`[]`, the clean app has none). Pass.
- `sast-semgrep` job log shows `semgrep scan --metrics=off --disable-version-check --sarif ...` and `installed semgrep-rules 16b9e6d45f10649f6a531ec4838ed9924372c3bc`. Pass.

### 2026-10-28, chunk 07 (secrets-stage)
Added `factory/stages/secrets.py`, `rules/gitleaks.toml`, `tests/test_secrets.py`, the `secrets` job in `factory.yml` (gate now needs it), the `secrets-integration` selftest job, Make target `secrets` and a Secrets stage section in `docs/pipeline.md`. Pushed with owner pre-approval.
- selftest run `40788074302`: `test`, `secrets-integration`, `lint-workflows`, `macos-smoke` all `success`; `249 passed, 1 skipped` (skip is the integration test in the plain `test` job, which has no Gitleaks). Pass.
- `secrets-integration` log: `test_integration_real_gitleaks_finds_secret_and_env_file PASSED`, `2 findings` (`generic-api-key` scanner, `committed-env-file` check). Pass.
- Same job: `grep -c REDACTED gitleaks.sarif` printed `1` and the test asserts the fake key is absent from the SARIF. Pass.
- `factory-test-web` run `40788134508` (workflow_dispatch): `setup`, `hello-ai`, `passthrough`, `secrets`, `gate` all `success`; downloaded `secrets` artifact has `findings.json` = `[]` and `gitleaks.sarif`. Pass.

### 2026-10-28, chunk 06 (walking-skeleton)
Added config schema and validator, run manifest, passthrough, stub gate, reusable workflow, stub template, `docs/pipeline.md`; stub committed to `factory-test-web`. Owner approved pushes. Fixed two automated-review issues (fail-closed gate, `PYTHONSAFEPATH`). Selftest `40758674587` green, `222 passed`, actionlint 0 errors, zizmor no findings.
- `gh run list --repo AakashDadhich/factory-test-web --workflow factory.yml`: run `40758255057`, event `push`, `success` (attempt 2 on fixed code). Pass.
- Jobs `setup`, `passthrough`, `hello-ai`, `gate` all `success`. Pass.
- `gh run download ... -n hello-ai`: `hello.json` `{"greeting": ..., "model": "claude-sonnet-5-5"}` matches `hello.schema.json`; meta `valid: true`. Pass.
- Gate summary: `PASS`, all five severities 0. Pass.
- Scratch branches with one `high` from passthrough: run `40759002513` gate `FAIL`, reason `1 critical or high finding(s)`. Both scratch branches deleted. Pass (`hello-ai` also failed there: Claude session limit; adapter now exits 75 for it).

### 2026-10-28, chunk 04 (model-adapter)
Added `factory/adapter/{__init__,__main__,claude_code,fake}.py`, `prompts/hello.md`, `schemas/hello.schema.json`, `.github/workflows/adapter-smoke.yml`, `tests/test_adapter.py`, `docs/adapter.md` and the `claude-code` lock entry. Flags read from local `claude --help` (2.1.286) and re-checked against the pinned 2.1.308 in the smoke workflow. Owner approved the push and the smoke run.
- Selftest run `40756115941`: `test`, `lint-workflows` and `macos-smoke` all `success`; `173 passed in 2.06s`, 41 of them in `test_adapter.py`, 0 failed. actionlint `Found total 0 errors` for `adapter-smoke.yml`; zizmor `No findings to report`. `macos-smoke` also `success` once a macOS runner freed up. Pass.
- `gh workflow run adapter-smoke.yml` (run `40756159124`): `hello: success`. CLI `2.1.308 (Claude Code)`, `all flags present`. Artifact `hello` has `{"greeting": "Hello, Security Software Factory, glad to be working with you!", "model": "claude-sonnet-5-5"}`, validated against `schemas/hello.schema.json` in CI; meta `attempts: 1`, `valid: true`, 3.7 s. Pass.
- `grep -n CLAUDE_CODE_OAUTH_TOKEN` on the smoke log: one hit, `CLAUDE_CODE_OAUTH_TOKEN: ***`; `grep -c sk-ant` is 0. Pass.
- `FACTORY_MODEL_ADAPTER=fake`: `test_fake_adapter_returns_canned_reply PASSED`. Pass.
(newest first: date, chunk, what was done, Done-when results)

### 2026-10-28, chunk 05 (web-test-project)
Built `AakashDadhich/factory-test-web`: Express 5 TypeScript app (`/health`, `/api/greeting`), 6 node:test + supertest tests, multi-stage Dockerfile, `openapi.yaml`, `.factory.yml`, `.env.example`, `.gitignore`, `.dockerignore`, Dependabot, `app-ci.yml`, README. The lockfile came from a throwaway `bootstrap/lockfile` branch (run `40750758840`: 122 packages, all from registry.npmjs.org with integrity, no install scripts). That branch briefly became the default; the owner approved switching the default to `main` and deleting it, which closed two Dependabot PRs (node 25, `@types/node` 26). The owner approved the pushes.
- `gh run list --repo AakashDadhich/factory-test-web --workflow app-ci.yml --limit 1`: `completed success` (run `40753679396`, main). Pass.
- CI log: `# tests 6`, `# pass 6`, `# fail 0` (the 4 required plus JSON 404 and oversized body), and `naming to docker.io/library/factory-test-web:ci done`. Pass.
- `.factory.yml` parsed with Ruby's YAML (no PyYAML on the Mac): `platform: web`. Pass.
- `git ls-files | grep -x .env`: prints nothing. Pass.

### 2026-10-28, chunk 03 (data-contracts)
Added the three schemas, `factory/findings.py`, `factory/sarif.py`, `factory/sbom.py`, `docs/contracts.md`, `tests/test_findings.py`, `tests/test_sarif.py`, `tests/test_sbom.py`, five fixtures and a `sarif contract check` step in selftest. Owner approved the push; selftest run `40750075295` green.
- `gh run view 40750075295`: `test`, `lint-workflows`, `macos-smoke` all `success`; `132 passed in 0.77s`, 89 of them in the three new test files. Pass.
- `python -m factory.sarif tests/fixtures/codeql.sarif --stage sast-codeql --tool codeql` (CI step and `test_cli_codeql_output_validates_and_is_stable PASSED`): output validates; `js/sql-injection` (security-severity 8.1) is `high`, 9.8 `critical`, 6.1 `medium`, 3.2 `low`. Pass.
- Fingerprint stability: `cmp first.json second.json` clean, both sha256 `fde562b2...fa42e2`; `test_fixtures_convert_to_valid_findings_with_stable_fingerprints` PASSED for all three fixtures. Pass.

### 2026-10-28, chunk 02 (pinned-tool-installer)
Added `tools/versions.lock`, `factory/tools.py`, `factory/platform_check.py`, `.github/actions/setup-factory/action.yml`, `.github/zizmor.yml`, `tests/test_tools.py`, `tests/test_platform_check.py`, `lint-workflows` and `macos-smoke` jobs, Make targets and the macOS `make` fact in `docs/runners.md`. Checksums taken from each release's published checksums file and cross-checked against GitHub's asset digests. First run (`40746307677`) failed zizmor (`github-env` x3, `self-repository` x3); fixed and re-run with owner approval.
- `gh run view 40746602330`: `test`, `lint-workflows`, `macos-smoke` all `success`. Pass.
- pytest log: `test_install_binary_rejects_wrong_checksum PASSED` and `test_main_checksum_mismatch_exits_non_zero PASSED`; `43 passed`. Pass.
- `lint-workflows` log: actionlint `Found total 0 errors`; zizmor `No findings to report. Good job! (1 ignored, 4 suppressed)`. Pass.
- Lock: gitleaks and actionlint `linux-x64` sha256 are 64 lowercase hex; no container entries yet (test enforces `@sha256:` for any added later). Pass.

### 2026-10-27, chunk 01 (factory-skeleton)
Added the folder layout, `factory` package, `pyproject.toml`, `requirements-dev.txt`, `Makefile`, smoke test, `selftest.yml`, `dependabot.yml`, `CLAUDE.md`, `README.md`, extended `.gitignore`, and `docs/runners.md` (verified against the runner-images readmes and GitHub's limits doc). Owner approved the push; selftest run `40605526763` green.
- `gh run list ... --workflow selftest.yml --limit 1`: `completed success` (run 40605526763). Pass.
- `gh run view 40605526763 --log | grep passed`: `1 passed in 0.02s`. Pass.
- `grep -E 'uses: [^@]+@[0-9a-f]{40}' selftest.yml`: 2 of 2 `uses:` lines pinned by SHA. Pass.
- `docs/runners.md`: 11 tools with yes/no and versions for both images, concurrency limits (20 / 5 macOS), time limits (6 h job, 35 days run), 3 source URLs, dated 2026-10-27. Pass.

### 2026-10-27, chunk 00 (accounts-and-repo-setup)
Created and tagged both public repos, wrote `docs/setup-repos.md` (endpoints checked against the GitHub REST docs), set up local git with `origin`, committed. Owner turned on 2FA, created and installed the App, ran `claude setup-token` and the loop. Design PDF kept local only (`plan/*.pdf` in `.gitignore`, never committed).
- Both repos: `PUBLIC`, topics `["security-factory"]`. Pass.
- Both repos: secret scanning `enabled`, push protection `enabled`. Pass.
- Both repos: secrets `CLAUDE_CODE_OAUTH_TOKEN`, `FACTORY_APP_PRIVATE_KEY`. Pass.
- Both repos: Dependabot secret `CLAUDE_CODE_OAUTH_TOKEN`. Pass.
- Both repos: variables `FACTORY_APP_ID` (`5502214`), `FACTORY_ALLOWED_ACTORS` (`AakashDadhich`). Pass.
- Both repos: `default_workflow_permissions` `read`, `can_approve_pull_request_reviews` false, fork approval `all_external_contributors`. Pass.
- App installed on `factory-test-web`: `gh api user/installations` returns 403 with the owner's OAuth token, and `GET /apps/{slug}` returns 404 because the App is private. Owner confirmed in Settings. Pass (manual).
- `git remote -v`: `origin https://github.com/AakashDadhich/security-factory.git`. Pass.
- `grep "gh secret set" docs/setup-repos.md`: lines 39, 40, 41; no secret values in the file. Pass.

## Starter prompt
Paste this into a fresh session, replacing `NN-<slug>`:

```
You are building one chunk of my Security Software Factory. Read only these two files first:
1. plan/PROGRESS.md
2. plan/NN-<slug>.md
Do not read other chunk files or the design document. Confirm the chunk's dependencies are marked done in PROGRESS.md; if not, stop and tell me. Use only the tools named in the chunk's Background (they come from decisions.md). Do the Tasks, leave the Outputs committed in small Conventional Commits, run every Done-when check and show me the results, then update PROGRESS.md (status, next up, notes, log). Ask before pushing.
```
