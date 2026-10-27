# Prerequisites

Everything you need before building the Security Software Factory. Tool choices are recorded in [decisions.md](decisions.md). Runner image facts were checked against `actions/runner-images` on 2026-10-26; chunk 01 re-checks them.

## 1. Accounts to create

| Account | Why you need it | Free? | Settings to enable |
|---|---|---|---|
| GitHub personal account (`AakashDadhich`, already exists) | Owns everything | Yes | Two-factor authentication (recommended for any account holding signing keys and tokens). No organisation is created (D21). |
| Public repo `AakashDadhich/security-factory` | Holds the scripts, prompts, rules and the reusable workflow | Yes | Public, so any repo can call its reusable workflow. Tagged with topic `security-factory` and configured by the per-repo setup loop (below). |
| Public test repos under `AakashDadhich` (`factory-test-web`, later `factory-vuln-web`, `factory-test-macos`, `factory-test-ios`, `factory-vuln-ios`) | Projects the factory runs against | Yes | Tagged with topic `security-factory` and configured by the per-repo setup loop: secret scanning, push protection, read-only default workflow permissions, approval for fork PR workflows, and (from chunk 30) an Actions allow list pinned by SHA. |
| GitHub App owned by your personal account (for example `aakashdadhich-factory-bot`) | Pushes generated code and fires the fix-loop event. Pushes made with the default `GITHUB_TOKEN` never start new workflow runs, so the loop needs an App token. | Yes | Repository permissions: Contents read/write, Issues read/write, Pull requests read/write, Metadata read. Install on selected project repos only. App ID goes in repo variable `FACTORY_APP_ID` and the private key in repo secret `FACTORY_APP_PRIVATE_KEY`, in every tagged repo (set by the setup loop). Keep the key in your password manager, because GitHub secrets can't be read back. |
| Claude subscription (existing, **Pro**) | Runs the AI stages through Claude Code | Paid (you already have it) | Run `claude setup-token` once with the Claude Code you already have, keep it in your password manager, and let the setup loop store it as repo secret `CLAUDE_CODE_OAUTH_TOKEN` and as a Dependabot repo secret of the same name in every tagged repo. Factory runs share your Pro usage limits. |

Not needed: a GitHub organisation (D21), Semgrep account, Docker Hub account, Snyk, or the Apple Developer Program (£79 a year, only needed if you ship to the App Store; the factory uses unsigned builds).

## 2. Tooling on the runners

Linux runner = `ubuntu-24.04`. macOS runner = `macos-15` (arm64). Nothing is installed on your Mac.

| Tool | Used for | Runner | How it gets there | Preinstalled? |
|---|---|---|---|---|
| git, Python 3.12, Node 22, jq, yq, make, shellcheck, pipx, Docker | Orchestrator, glue, containers | Linux | Runner image | Yes |
| git, Python 3.14, Node 22, jq, Homebrew, Xcode 16.4 (Xcode 26.x also present) | Apple builds | macOS | Runner image | Yes. **No Docker. make not listed** (chunk 02 checks and installs if missing) |
| Claude Code CLI | Every AI stage, through the adapter | Linux | `npm install -g @anthropic-ai/claude-code@<exact version>` | No |
| Semgrep Community Edition | SAST for TypeScript and Swift, plus pre-commit hook | Linux | `pipx install semgrep==<exact>`; rules vendored from `semgrep/semgrep-rules` at a pinned commit; always `--metrics=off` | No |
| CodeQL | Deep data-flow SAST: JS/TS on Linux, Swift on macOS | Linux and macOS | `github/codeql-action` pinned by commit SHA; bundle version pinned in its config | Bundle preinstalled on Linux |
| ESLint + `eslint-plugin-security` + `eslint-plugin-no-unsanitized` | Extra JS/TS SAST | Linux | `npm ci` from a lockfile kept in the factory repo | No |
| SwiftLint | Swift lint rules with security focus | macOS | Release binary, SHA-256 checked | No (no longer on the macOS image) |
| Gitleaks | Secrets in full git history, plus pre-commit hook | Linux | Release binary, SHA-256 checked | No |
| OSV-Scanner | Dependency vulnerabilities (npm, SwiftPM) | Linux | Release binary, SHA-256 checked | No |
| Syft | CycloneDX SBOM | Linux | Release binary, SHA-256 checked | No |
| Grype | Vulnerability scan of the SBOM | Linux | Release binary, SHA-256 checked; vulnerability DB downloaded per run and its build date recorded | No |
| OWASP ZAP | Web DAST | Linux | Container image pinned by digest (`ghcr.io/zaproxy/zaproxy@sha256:...`) | No |
| MobSF | Static analysis of the iOS `.ipa` | Linux (needs Docker; the `.ipa` is built on macOS and passed as an artifact) | Container image pinned by digest | No |
| pytm | Threat model as code | Linux | `pip install pytm==<exact>` | No |
| pre-commit | Runs Semgrep and Gitleaks before each bot commit | Linux | `pipx install pre-commit==<exact>` | No |
| XcodeGen | Generates Xcode projects for the Apple test apps | macOS | Release binary, SHA-256 checked | No |
| actionlint, zizmor | Lint the factory's own workflow files | Linux | Release binary / `pipx install zizmor==<exact>` | No |

**How versions are pinned.** One file, `tools/versions.lock`, lists every tool with its exact version, download URL, and SHA-256 or container digest. The installer (`python -m factory.tools install <name>`) refuses to run anything whose checksum doesn't match. Third-party GitHub Actions are pinned by full commit SHA, never by tag, because tags can be moved (as happened in the 2025 `tj-actions/changed-files` compromise). Changing what the gate catches always goes through a reviewed commit to the factory and a deliberate move of the `v1` tag.

## 3. Things that are not free, or have limits

1. **Public repos only stay free.** All your project repos will be public (decision P1), so standard runner minutes, including macOS, cost nothing. If a repo ever goes private, it gets 2,000 minutes a month on the Free plan, and macOS minutes count 10x (about 200 macOS minutes). Beyond that you'd pay about £0.0045 a minute for Linux and £0.047 a minute for macOS (converted from GitHub's USD price list; check GitHub's billing page).
2. **CodeQL and the Security tab** are free on public repos only.
3. **Required status checks** (branch rulesets) are free on public repos only on the Free plan.
4. **No account-level secrets on a personal account.** Secrets, variables and Actions settings are set per repo. The setup loop in `docs/setup-repos.md` (chunk 00) applies them to every repo tagged `security-factory`, and is re-run when you add a repo or rotate the Claude token (about yearly) or the App key.
5. **Concurrency.** The design document says 20 concurrent jobs per account, 5 of them macOS. Extra jobs queue rather than fail. Chunk 01 confirms the current figures.
6. **Artifacts expire** after at most 90 days, so each project's record lives on a `factory-record` git branch (D15).
7. **Claude Pro usage limits.** Every spec run uses several AI stages, and up to 2 fix iterations. A run that hits the limit must fail cleanly with a clear message.
8. **MobSF iOS dynamic analysis needs Corellium, which is paid.** MobSF also doesn't support macOS apps. Apple "DAST" is MobSF static analysis (iOS) plus scripted checks (iOS and macOS).
9. **Semgrep CE has few Swift rules.** Expect to write custom rules.
10. **Prompt injection.** The AI stages read repo content that may be hostile. AI jobs get read-only tokens and a tool allowlist, and never see the App private key.
11. **Dependabot PRs** can't read normal Actions secrets. The Claude token must also be stored as a Dependabot secret.

## 4. Decisions you made before starting

| # | Question | Answer |
|---|---|---|
| P1 | Project repo visibility | All public |
| P2 | Claude plan | Pro |
| P3 | What triggers a run | Both: a labelled issue (`factory:spec`, `factory:change`) runs the full pipeline with code generation; every push and PR runs check mode |
| P4 | How generated code lands | Direct commits by the bot to branch `factory/<issue-number>`, never to the default branch |
| P5 | Fix loop cap | 2 iterations |
| P6 | Orchestrator language | Python (pytest) |
| P7 | Web stack | Node + Express, TypeScript |
| P8 | Owner and factory repo names | Personal account `AakashDadhich`, repo `security-factory` (no organisation, D21) |
