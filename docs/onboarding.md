# Onboarding a new project

A new project gets the factory by being created from the template repository `AakashDadhich/factory-project-template`. The template holds the stub that calls the factory at `@v1`, a `.factory.yml` with examples, Dependabot config, `.env.example`, a `.gitignore` that ignores `.env`, `security/README.md` and `SECURITY.md`. Its source of truth is `templates/project/` in this repo; copy changes across by hand.

Every project repo is public (P1).

## Steps

1. **Create the repo.** On the template repo choose "Use this template", then "Create a new repository" under `AakashDadhich`, public. Or: `gh repo create AakashDadhich/<name> --template AakashDadhich/factory-project-template --public --clone`.
2. **Pick the platform.** In `.factory.yml` uncomment the `web`, `macos` or `ios` block and edit it (port, health path, Dockerfile, OpenAPI spec for web; XcodeGen spec and scheme for Apple). The schema is described in `docs/pipeline.md` ("Project config"). Delete the ecosystems you don't use from `.github/dependabot.yml`.
3. **Tag the repo** so the setup loop finds it: `gh repo edit AakashDadhich/<name> --add-topic security-factory`.
4. **Add the repo to the App installation.** Settings, Applications, Installed GitHub Apps, the factory App, Configure, Repository access. The bot needs this to commit to `factory/<issue>` branches and write the `factory-record` branch.
5. **Run the per-repo setup loop** from `docs/setup-repos.md`. Template repos never copy secrets, variables or Actions settings, so this step is required. It sets the Claude token, the App key and ID, the allowed actors, labels, workflow permissions, fork approval, secret scanning and the Actions allow list.
6. **Let the first run finish on the default branch.** Push to `main` (or run the workflow by hand) and wait for `factory / gate`.
7. **Add the required-check ruleset** `factory-gate` (`docs/required-check.md`). Only do this after the check has run once.
8. **Open a `factory:spec` issue** describing the feature in plain words. The factory plans it, threat-models it, builds it on `factory/<issue>`, and comments the result. Use `factory:change` for later changes.

## Rotating credentials

| Credential | Lifetime | How to rotate |
|---|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | about a year (`claude setup-token`) | Run `claude setup-token`, save the new token in your password manager, re-run the setup loop with it |
| `FACTORY_APP_PRIVATE_KEY` | until you revoke it | Generate a new key in the App settings, save the `.pem` in your password manager, re-run the setup loop with a temporary copy, then delete the old key in the App settings and the temporary `.pem` |

The loop overwrites the secrets in every repo tagged `security-factory`, so one run rotates them all. Re-running it on repos that are already set up is safe. Details are in the "When to run it" section of `docs/setup-repos.md`.
