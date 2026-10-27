# Decisions

Single source of truth for every tool and design choice. Chunks use only what is chosen here. Only the owner (Aakash) changes this file; build agents never edit it. Decided on 2026-10-26; D21 added on 2026-10-27.

## Setup decisions

| # | Decision | Chosen | Rejected | Reason |
|---|---|---|---|---|
| P1 | Project repo visibility | All public | Mixed, all private | Keeps macOS minutes, CodeQL and required checks free |
| P2 | Claude plan | Pro | Max | Owner's existing plan; prompts kept lean, AI stages fail cleanly on usage limits |
| P3 | Run triggers | Spec mode: issue labelled `factory:spec` or `factory:change` runs the full pipeline with code generation. Check mode: every push and PR runs the security stages and gate | Spec only; push only | Covers both AI-built and hand-written changes |
| P4 | How generated code lands | Bot commits directly to branch `factory/<issue-number>`; never to the default branch. The owner merges | Bot opens a PR | Owner's preference |
| P5 | Fix loop cap | 2 iterations, then fail and comment on the issue | 1, 3 | Protects the Pro usage window |
| P6 | Orchestrator language | Python 3.12, pytest | Bash | Preinstalled on both runners, good JSON/SARIF handling, testable |
| P7 | Web stack for test apps | Node + Express, TypeScript | Python + Flask, Next.js | Owner's stack |
| P8 | Owner and repo names | Personal account `AakashDadhich`, factory repo `AakashDadhich/security-factory` | A free GitHub organisation | See D21 |

## Tool decisions (in pipeline order)

| # | Group | Chosen | Rejected or deferred | Reason |
|---|---|---|---|---|
| D1 | Planning framework | OWASP ASVS (primary) + abuse-case user stories (one per feature) | OWASP SAMM: deferred to chunk 31 (self-assessment of the factory) | ASVS is the document's recommended primary; abuse cases are cheap and feed the threat model |
| D2 | Default ASVS level | Level 2. The plan stage may raise it to Level 3 based on its risk rating, never lower it. `.factory.yml` may set it explicitly | Level 1 default; free choice each run | Most apps handle some personal data |
| D3 | Threat modelling method | STRIDE always. LINDDUN added when the plan flags personal data. Attack trees added for features rated high risk | STRIDE only; LINDDUN always | Deterministic triggers keep Pro usage predictable |
| D4 | Threat modelling tooling | pytm (threat model as Python code, stored in the project record) | OWASP Threat Dragon; factory JSON only | Re-runnable and diffable, which the improvement loop needs |
| D5 | Secure code generation layers | All four: security rules file; secure-by-default patterns; pre-commit hooks (Semgrep + Gitleaks via the `pre-commit` framework) **on the runner, for bot commits only**; second-agent security review | none | Layers stack; no tools on the owner's Mac |
| D6 | SAST | Semgrep Community Edition (primary, all platforms) + CodeQL (JS/TS on Linux, Swift on macOS) + ESLint security plugins (`eslint-plugin-security`, `eslint-plugin-no-unsanitized`, web) + SwiftLint (Apple) | none | All free on public repos; tools miss different things |
| D7 | Dependency scanning | OSV-Scanner (primary) + Dependabot (update PRs) | Trivy, npm audit | Grype (D8) already gives a second vulnerability opinion |
| D8 | SBOM | Syft generates CycloneDX JSON; Grype scans it | SPDX format; Syft without Grype | One SBOM format end to end |
| D9 | Secrets detection | Gitleaks binary: pre-commit hook + full history scan in the pipeline | TruffleHog (later, if false positives become noisy) | Any committed secret is rotated whether live or not |
| D10 | Secrets management | **Open / deferred** for the owner's apps. Only the factory's own credentials are GitHub repo secrets, set per repo (D21) (`CLAUDE_CODE_OAUTH_TOKEN`, `FACTORY_APP_PRIVATE_KEY`). GitHub secret scanning and push protection on every repo. Secrets never in workflow YAML or a committed `.env`; only `.env.example` with fake values is committed | SOPS with age (deferred) | Owner's apps don't need secrets management yet |
| D11 | Web DAST | OWASP ZAP in a container against a throwaway container of the app: baseline (passive) scan first, then active scan. OpenAPI import from the start whenever the project has an OpenAPI file. Authenticated scanning in a later chunk (25) | Nuclei (later) | Nuclei templates target CVEs in off-the-shelf products |
| D12 | iOS and macOS DAST | MobSF **static** analysis of the unsigned iOS `.ipa`, run in Docker on Linux. Scripted checks on iOS and macOS: entitlements, App Transport Security, Keychain use, sandboxing, hardened runtime, privacy manifests | MobSF dynamic analysis (needs paid Corellium); MobSF for macOS (not supported) | Free options only |
| D13 | Orchestration glue | Make (thin targets) calling `python -m factory.<module>`. Dagger later | Just | Make is preinstalled on Linux; no lock-in |
| D14 | Optional extras | Model Context Protocol: later. Ollama: later | none ruled out | Not needed for the first adapter; the adapter interface leaves room |

## Design decisions (gaps in the design document, resolved with the owner)

| # | Decision | Chosen | Rejected | Reason |
|---|---|---|---|---|
| D15 | Where each project's record lives | Two parts. (1) The living plan and threat model (`security/plan.json`, `security/tm.py`, `security/threats.json`, `security/attack-trees/`) are committed with the code on `factory/<issue>`, so they merge together. (2) Orphan branch `factory-record` holds run history: `runs/<timestamp>-<run_id>.json` for every gate result, and `latest/` (`sbom.cdx.json`, `findings.json`, `run-manifest.json`) updated on each gate pass of a default-branch push. Pushes to it never trigger runs | Actions artifacts (expire); everything on the record branch (would drift from unmerged code) | Permanent, diffable, no loops or branch-protection clashes |
| D16 | How the fix loop restarts | A failed gate with iteration < 2 sends `repository_dispatch` type `factory-fix` with payload `{issue, iteration, findings_run_id}`. Fix mode re-runs code generation on those findings, then every security stage. At the cap: comment the report on the issue and fail | Manual re-label | Actions runs can't loop back; the counter stops runaway loops |
| D17 | Factory versioning | Project stubs call the factory at tag `@v1`. The owner moves `v1` only after the factory self-test and both acceptance tests pass | `@main` | Projects pick up updates, but only known-good ones |
| D18 | AI stages in check mode | Threat-model update and second-agent review run on pull requests and on pushes to the default branch only. Scanners and gate run on every push | Every push | Saves Pro usage on work-in-progress pushes |
| D19 | AI review findings and the gate | High and critical findings from the second-agent review block the gate like scanner findings, suppressible in `suppressions.yml` with reason and expiry | Warn only | Consistent gate behaviour |
| D20 | Linting the factory's own workflows | actionlint + zizmor (pinned) run in the factory self-test | none | Catches injection and permission mistakes in workflow files |
| D21 | Where the factory lives | Personal account `AakashDadhich`, no organisation. Personal accounts have no account-level Actions secrets or variables and no account-wide Actions policy, so every repo that runs the factory (including `security-factory`) holds its own repo secrets `CLAUDE_CODE_OAUTH_TOKEN` and `FACTORY_APP_PRIVATE_KEY`, Dependabot secret `CLAUDE_CODE_OAUTH_TOKEN`, and repo variables `FACTORY_APP_ID` and `FACTORY_ALLOWED_ACTORS`. These repos are tagged with topic `security-factory`; one `gh` loop in `docs/setup-repos.md` (written in chunk 00) sets the credentials and the per-repo hardening (read-only default token, fork-PR approval, secret scanning, push protection, and from chunk 30 the Actions allow list) on every tagged repo. The same loop handles onboarding and rotation. The GitHub App is owned by the personal account and installed on selected repos | A free GitHub organisation with org-level secrets and policy (the design document's suggestion) | Owner's preference: an org is overkill for about six repos and a solo owner. Exposure is similar (org secrets visible to all repos reach the same places). The cost is per-repo setup, made one command by the loop. Revisit if the number of projects grows past about 10 to 15 or collaborators join; repos can be transferred into an org later |

## Open decisions (no chunk depends on these)

| Item | Status |
|---|---|
| D10 secrets management for apps (SOPS/age) | Deferred |
| Dagger | Later |
| Model Context Protocol, Ollama | Later |
| Nuclei, TruffleHog | Later |
