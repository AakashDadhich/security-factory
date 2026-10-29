# Per-repo setup loop

The factory runs under the personal account `AakashDadhich`, which has no account-level Actions secrets, variables or policy. Every repo that runs the factory therefore holds its own copy of the credentials and its own Actions hardening. This loop sets all of that in one go for every repo tagged with the topic `security-factory`.

Run it yourself, in your own terminal. Secret values are typed or read from a file locally and go straight to GitHub; they never pass through an agent session or get written to disk by the loop.

## What it sets, per repo

| Kind | Name | Value |
|---|---|---|
| Actions secret | `CLAUDE_CODE_OAUTH_TOKEN` | Claude token from `claude setup-token` |
| Dependabot secret | `CLAUDE_CODE_OAUTH_TOKEN` | same token (Dependabot runs can't read Actions secrets) |
| Actions secret | `FACTORY_APP_PRIVATE_KEY` | GitHub App private key (`.pem` contents) |
| Actions variable | `FACTORY_APP_ID` | GitHub App ID |
| Actions variable | `FACTORY_ALLOWED_ACTORS` | `AakashDadhich` |
| Setting | default workflow permissions | `read`, and Actions may not approve PRs |
| Setting | fork PR workflow approval | required for all external contributors |
| Setting | secret scanning, push protection | enabled |

## Before you start

- `gh auth status` shows `AakashDadhich` with the `repo` and `workflow` scopes.
- The Claude token and the App `.pem` are in your password manager. GitHub secrets are write-only, so the password manager is the only place to get them back.
- Put a temporary copy of the `.pem` somewhere local and note its path. The loop reminds you to delete it at the end.
- Every target repo is tagged: `gh repo edit AakashDadhich/<repo> --add-topic security-factory`.

## The loop

Paste the whole block into zsh or bash. It runs in a subshell, so the token variable never outlives it.

```bash
(
  printf 'Claude token: '; read -rs CLAUDE_TOKEN; echo
  printf 'Path to temporary App .pem: '; read -r PEM
  printf 'App ID: '; read -r APP_ID
  [ -n "$CLAUDE_TOKEN" ] && [ -r "$PEM" ] && [ -n "$APP_ID" ] || { echo "Missing token, readable .pem or App ID. Nothing changed."; exit 1; }
  for r in $(gh repo list AakashDadhich --topic security-factory --limit 200 --json nameWithOwner --jq '.[].nameWithOwner'); do
    echo "== $r"
    printf %s "$CLAUDE_TOKEN" | gh secret set CLAUDE_CODE_OAUTH_TOKEN --repo "$r"
    printf %s "$CLAUDE_TOKEN" | gh secret set CLAUDE_CODE_OAUTH_TOKEN --repo "$r" --app dependabot
    gh secret set FACTORY_APP_PRIVATE_KEY --repo "$r" < "$PEM"
    gh variable set FACTORY_APP_ID --repo "$r" --body "$APP_ID"
    gh variable set FACTORY_ALLOWED_ACTORS --repo "$r" --body AakashDadhich
    gh label create factory:spec --repo "$r" --force --color 5319e7 --description "Factory: plan and build this spec"
    gh label create factory:change --repo "$r" --force --color 1d76db --description "Factory: plan a change to this project"
    gh label create factory:needs-human --repo "$r" --force --color B60205 --description "The factory gave up fixing this issue"
    gh api -X PUT "repos/$r/actions/permissions/workflow" \
      -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
    gh api -X PUT "repos/$r/actions/permissions/fork-pr-contributor-approval" \
      -f approval_policy=all_external_contributors
    printf '%s' '{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}' \
      | gh api -X PATCH "repos/$r" --input - --silent
  done
  unset CLAUDE_TOKEN
  echo "Done. Now delete the temporary key: rm \"$PEM\""
)
```

Endpoints used, checked against the GitHub REST docs on 2026-10-27:

- `PUT /repos/{owner}/{repo}/actions/permissions/workflow` with `default_workflow_permissions` (`read`/`write`) and `can_approve_pull_request_reviews` (boolean).
- `PUT /repos/{owner}/{repo}/actions/permissions/fork-pr-contributor-approval` with `approval_policy` (`first_time_contributors_new_to_github`, `first_time_contributors` or `all_external_contributors`).
- `PATCH /repos/{owner}/{repo}` with `security_and_analysis.secret_scanning.status` and `security_and_analysis.secret_scanning_push_protection.status` (`enabled`/`disabled`).

## Check one repo

```bash
r=AakashDadhich/security-factory
gh secret list --repo "$r"
gh secret list --repo "$r" --app dependabot
gh variable list --repo "$r"
gh api "repos/$r/actions/permissions/workflow" --jq .default_workflow_permissions
gh api "repos/$r" --jq '.security_and_analysis.secret_scanning.status, .security_and_analysis.secret_scanning_push_protection.status'
```

## When to run it

### After adding a repo
1. Tag it: `gh repo edit AakashDadhich/<repo> --add-topic security-factory`.
2. If the repo needs the bot, add it to the App installation: Settings > Applications > Installed GitHub Apps > the factory App > Configure > Repository access.
3. Run the loop. Re-running it on repos that are already set up is safe; it overwrites with the same values.

### After rotating the Claude token (about yearly)
1. Run `claude setup-token` and save the new token in your password manager.
2. Run the loop with the new token.

### After generating a new App key
1. In the App settings, generate a new private key and save the `.pem` contents in your password manager.
2. Run the loop with a temporary copy of the new `.pem`.
3. Once the loop has finished, delete the old key in the App settings, then delete the temporary `.pem`.
