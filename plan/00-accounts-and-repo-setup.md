# 00. Accounts and repo setup

## Goal
Get every repo, credential and GitHub setting the factory needs in place under the personal account `AakashDadhich` (no organisation, D21). The owner does anything that involves a secret value. Write the per-repo setup loop that every later repo reuses, and turn the local folder into a git repo linked to the new factory repo.

## Inputs
- `plan/PROGRESS.md` (Notes section, to fill in)
- This file
- The owner, at the keyboard. This chunk is mostly manual. The agent guides, runs safe `gh` commands with the owner's approval, and never sees a secret value.

## Tasks
1. Confirm with the owner that the factory repo is `AakashDadhich/security-factory`. Record the owner and repo in PROGRESS.md Notes.
2. Check `gh auth status` shows `AakashDadhich` with the `repo` and `workflow` scopes. If not, ask the owner to run `gh auth refresh -s repo,workflow`.
3. Owner, in the browser: make sure two-factor authentication is on for the account (recommended for any account holding signing keys and tokens).
4. With the owner's approval, create two public repos, and tag both with the topic `security-factory`. The setup loop finds repos by this topic.
   ```bash
   gh repo create AakashDadhich/security-factory --public
   gh repo create AakashDadhich/factory-test-web --public
   gh repo edit AakashDadhich/security-factory --add-topic security-factory
   gh repo edit AakashDadhich/factory-test-web --add-topic security-factory
   ```
5. Owner creates the GitHub App in the browser (personal Settings > Developer settings > GitHub Apps > New GitHub App):
   - Name `aakashdadhich-factory-bot` (App names are global, so adjust if taken), homepage = factory repo URL, Webhook **inactive**.
   - Repository permissions: Contents read/write, Issues read/write, Pull requests read/write, Metadata read. No account permissions.
   - "Only on this account". Create it, note the App ID, then generate a private key (a `.pem` downloads).
   - Install the App on the account, choosing "Only select repositories": `factory-test-web` for now.
   - The owner saves the `.pem` contents and, later, the Claude token in their password manager. GitHub secrets are write-only, so the setup loop needs these values again for each new repo and each rotation.
6. Write `docs/setup-repos.md` in the factory checkout. It holds the per-repo setup loop as one copy-paste block, which the owner runs in their own terminal so values never pass through the agent:
   - Prompt once, without echo, for the Claude token (`printf 'Claude token: '; read -rs CLAUDE_TOKEN; echo`). Ask for the path to a temporary copy of the App `.pem` and for the App ID.
   - For each repo in `gh repo list AakashDadhich --topic security-factory --json nameWithOwner --jq '.[].nameWithOwner'`:
     - `printf %s "$CLAUDE_TOKEN" | gh secret set CLAUDE_CODE_OAUTH_TOKEN --repo "$r"`, and the same with `--app dependabot`.
     - `gh secret set FACTORY_APP_PRIVATE_KEY --repo "$r" < "$PEM"`.
     - `gh variable set FACTORY_APP_ID --repo "$r" --body "$APP_ID"` and `gh variable set FACTORY_ALLOWED_ACTORS --repo "$r" --body AakashDadhich`.
     - Hardening through `gh api`:
       - default workflow permissions `read`, and Actions may not approve PRs (`PUT repos/{r}/actions/permissions/workflow`),
       - fork PR workflows need approval for all outside contributors (`PUT repos/{r}/actions/permissions/fork-pr-contributor-approval`),
       - secret scanning and push protection on (`PATCH repos/{r}` with `security_and_analysis`).
   - Finish with `unset CLAUDE_TOKEN` and a reminder to delete the temporary `.pem`.
   - Check each endpoint against the current GitHub REST docs before writing it down.
   - Short sections cover when to run the loop: after adding a repo, after rotating the Claude token (about yearly), and after generating a new App key. For a new App key, delete the old key in the App settings once the loop has finished.
7. The owner runs `claude setup-token` (with the Claude Code they already have), then runs the loop from `docs/setup-repos.md`. It sets up both tagged repos. The factory repo needs the secrets too, for `adapter-smoke.yml` and `acceptance.yml`.
8. Link the local folder:
   - In `/Users/aakash/Documents/projects/secure-software-factory`, run `git init -b main` and `git remote add origin https://github.com/AakashDadhich/security-factory.git`.
   - Commit `plan/` with `docs: add factory build plan`, and `docs/setup-repos.md` with `docs: add per-repo setup loop`.
   - Ask the owner before pushing.
9. Fill in PROGRESS.md Notes (owner, repo, App name, topic, variable and secret names) and log the session.

## Outputs
- A local git repo with `plan/` and `docs/setup-repos.md` committed, pushed to `AakashDadhich/security-factory` once the owner approves.
- PROGRESS.md Notes filled in.
- On GitHub:
  - two public repos tagged `security-factory`,
  - the App installed on `factory-test-web`,
  - in both repos: repo secrets `CLAUDE_CODE_OAUTH_TOKEN` and `FACTORY_APP_PRIVATE_KEY`, Dependabot secret `CLAUDE_CODE_OAUTH_TOKEN`, and repo variables `FACTORY_APP_ID` and `FACTORY_ALLOWED_ACTORS`,
  - in both repos: read-only default workflow permissions, fork-PR approval, secret scanning and push protection.

## Done when
For `R` in `security-factory` and `factory-test-web` (owner `AakashDadhich`):
- `gh repo view AakashDadhich/R --json visibility,repositoryTopics --jq '.visibility, [.repositoryTopics[].name]'` prints `PUBLIC` and a list containing `security-factory`.
- `gh api repos/AakashDadhich/R --jq '.security_and_analysis.secret_scanning.status, .security_and_analysis.secret_scanning_push_protection.status'` prints `enabled` twice.
- `gh secret list --repo AakashDadhich/R` lists `CLAUDE_CODE_OAUTH_TOKEN` and `FACTORY_APP_PRIVATE_KEY`.
- `gh secret list --repo AakashDadhich/R --app dependabot` lists `CLAUDE_CODE_OAUTH_TOKEN`.
- `gh variable list --repo AakashDadhich/R` lists `FACTORY_APP_ID` and `FACTORY_ALLOWED_ACTORS`.
- `gh api repos/AakashDadhich/R/actions/permissions/workflow --jq .default_workflow_permissions` prints `read`.

Also:
- The App is installed on `factory-test-web`. Check with `gh api user/installations --jq '.installations[].app_slug'`, or the owner confirms in Settings > Applications > Installed GitHub Apps.
- `git -C /Users/aakash/Documents/projects/secure-software-factory remote -v` shows the factory repo.
- `grep -n "gh secret set" docs/setup-repos.md` shows the loop, and the file contains no secret values.

## Size
S (about 45 minutes, mostly the owner clicking through GitHub).

## Dependencies
- Needs: none.
- Parallel: none. Every other chunk depends on this one.

## Background

### From the design document
> "Caveat: for a private central repo to be callable from your other repos, sharing must be enabled in its settings, and on a free plan the simplest route is making the factory repo public, which suits a portfolio piece anyway."

> "Every tool in this factory is free and open source; the only paid item is your existing Claude Code subscription."

> "GitHub Actions encrypted secrets for the pipeline."

The document suggests a free organisation so that secrets and variables are defined once. D21 deliberately departs from this: the owner chose the personal account. The trade-off is that secrets, variables and Actions hardening are set per repo, which the setup loop in `docs/setup-repos.md` makes a single command.

### Decisions that apply
- P1: all project repos are public. P2: Claude Pro. P8: owner `AakashDadhich`, factory repo `security-factory`.
- D21:
  - Personal account, no organisation. Personal accounts have no account-level Actions secrets or variables and no account-wide Actions policy.
  - Every repo that runs the factory, including `security-factory`, holds its own copies of the credentials. It is tagged with topic `security-factory` and configured by the setup loop.
  - The same loop is used for onboarding and rotation.
- D10: only the factory's own credentials are GitHub secrets. Secret scanning and push protection are on for every repo. Never put secrets in workflow YAML or a committed `.env`. Commit only `.env.example` with fake values.
- Why a GitHub App: pushes made with the default `GITHUB_TOKEN` never start new workflow runs, and the fix loop (D16) needs the bot's pushes and `repository_dispatch` events to start runs. An App gives short-lived tokens and a bot identity, which a personal access token wouldn't.
- Dependabot-triggered runs can't read Actions secrets, so the Claude token is also stored as a Dependabot secret in each repo.

### Factory facts (shared by every chunk)
- The factory is one public GitHub repo, `AakashDadhich/security-factory` (a personal account, no organisation; see D21), checked out at `/Users/aakash/Documents/projects/secure-software-factory`. It serves every project: iOS, macOS and web apps.
- The orchestrator is plain deterministic Python, not an AI. AI runs only inside specific stages, always through the model adapter.
- All jobs run on GitHub-hosted runners. Nothing from the factory is installed on the owner's Mac.
- Owner conventions: Conventional Commits; no em dashes in anything written; no code comments unless genuinely non-obvious; tests for all new logic; ask before any push or GitHub settings change.
