# New project

This repository was created from the Security Software Factory project template. The factory scans every push and pull request, and builds features from `factory:spec` issues.

## Onboarding

1. In `.factory.yml`, uncomment the block for your platform (`web`, `macos` or `ios`) and edit it.
2. Tag this repo with the topic `security-factory`.
3. Add this repo to the factory GitHub App installation (Settings, Applications, Installed GitHub Apps, Configure).
4. Run the per-repo setup loop from `docs/setup-repos.md` in the factory repo. Template repos never copy secrets, so this step is required.
5. After the first run on the default branch, add the `factory-gate` ruleset so `factory / gate` is a required check (`docs/required-check.md` in the factory repo).
6. Open an issue describing a feature and add the label `factory:spec`.

The full guide is `docs/onboarding.md` in [security-factory](https://github.com/AakashDadhich/security-factory).

## What is here

- `.github/workflows/factory.yml`: the stub that calls the factory at `@v1`
- `.github/dependabot.yml`: weekly updates for npm, Swift, Docker and GitHub Actions (delete the ecosystems you don't use)
- `.factory.yml`: project config, examples for each platform
- `.env.example` and `.gitignore`: `.env` is ignored and never committed
- `security/`: written by the factory, see `security/README.md`
- `SECURITY.md`: how to report a vulnerability
