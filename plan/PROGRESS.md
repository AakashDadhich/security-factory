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
| 02 | pinned-tool-installer | todo |
| 03 | data-contracts | todo |
| 04 | model-adapter | todo |
| 05 | web-test-project | todo |
| 06 | walking-skeleton | todo |
| 07 | secrets-stage | todo |
| 08 | sast-semgrep | todo |
| 09 | sast-codeql-eslint-web | todo |
| 10 | deps-and-sbom | todo |
| 11 | gate-and-report | todo |
| 12 | dast-zap-baseline | todo |
| 13 | dast-zap-active-openapi | todo |
| 14 | project-record | todo |
| 15 | security-rules-and-renderer | todo |
| 16 | clarify-plan-stage | todo |
| 17 | threat-model-pytm-stride | todo |
| 18 | threat-model-linddun-attacktrees | todo |
| 19 | secure-codegen-stage | todo |
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
Chunks 02 (pinned-tool-installer), 03 (data-contracts) and 05 (web-test-project) can now start, and can run in parallel. Check `plan/00-index.md` for their other dependencies.

## Open decisions
- D10: secrets management for apps (SOPS/age), deferred.
- Later: Dagger, Model Context Protocol, Ollama, Nuclei, TruffleHog.

## Notes for next session
- Owner: personal account `AakashDadhich` (no organisation, D21)
- Factory repo: `AakashDadhich/security-factory` (confirmed in chunk 00). Test web repo: `AakashDadhich/factory-test-web`. Both public, empty apart from the factory repo's first push.
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

## Session log
(newest first: date, chunk, what was done, Done-when results)

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
