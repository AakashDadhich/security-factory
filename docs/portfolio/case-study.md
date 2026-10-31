# Security Software Factory: a case study

A pipeline on GitHub Actions that takes an app idea (iOS, macOS or web) from a written spec to checked code, with security work at every step. One public repository, [AakashDadhich/security-factory](https://github.com/AakashDadhich/security-factory), serves every project. It costs nothing beyond an existing Claude Pro subscription.

Related pages: [diagrams](diagrams.md), [stages](stages.md), [securing the factory](factory-security.md), [OWASP SAMM self-assessment](samm.md), [limits](limits.md).

## The problem

When AI writes code, security review tends to arrive late or not at all. The usual fixes are a single scanner bolted on at the end, or a person reading diffs. Neither scales to a hobbyist who ships iOS, macOS and web apps and has no security team. I wanted the checks to be the same for every app, to run on every change, and to fail loudly when something is wrong.

## The approach

The design principle is to keep the intelligence swappable and everything else deterministic. The orchestrator is plain Python, not an AI. It decides which stage runs, passes artifacts between stages and enforces the gate. AI appears only inside specific stages: planning, threat modelling, code generation and security review. The pipeline logic never depends on any one model.

Each project holds a small stub workflow that calls the factory's reusable workflow, pinned to the `v1` tag. The factory then runs in one of four modes (details in [pipeline.md](../pipeline.md)):

- **Spec mode.** An issue labelled `factory:spec` produces a plan, a threat model and code on a branch named `factory/<issue>`. The bot never commits to the default branch, so a human merges.
- **Change mode.** An issue labelled `factory:change` updates the existing plan and threat model and only re-analyses the parts that changed.
- **Fix mode.** If the gate fails, the factory sends itself a `factory-fix` event and tries again, at most twice. After that it comments on the issue and labels it `factory:needs-human`.
- **Check mode.** Every push and pull request runs the scanners and the gate, for code the factory did not write.

Tool and design choices are recorded in [plan/decisions.md](../../plan/decisions.md), decisions D1 to D21 and P1 to P8, so each pick has a stated reason and a rejected alternative.

## The pipeline

A run goes: authorize, plan, threat model, generate code, commit, second-agent review, then the scanners in parallel, then the gate. The plan uses OWASP ASVS (level 2 by default, raised to 3 for high-risk work) and an abuse case per feature. The threat model is pytm code plus STRIDE, with LINDDUN when personal data is involved and attack trees for high-risk features. Code generation is constrained by four layers: a rendered rules file, secure-by-default patterns, pre-commit hooks (Semgrep and Gitleaks) run by the runner, and a separate review agent.

The scanners are Gitleaks, Semgrep, CodeQL, ESLint security plugins, SwiftLint, OSV-Scanner, Syft and Grype, OWASP ZAP, MobSF, and a set of scripted Apple checks. The gate merges and de-duplicates their findings, applies the policy and fails closed: a stage that is missing, failed or skipped without a valid reason becomes a critical finding that cannot be suppressed. Every stage is described in [stages.md](stages.md).

Each project also keeps a record. The living plan and threat model are committed under `security/` and merge with the code. An orphan branch, `factory-record`, holds run history and the latest SBOM and findings ([record.md](../record.md)).

## Model portability

All AI calls go through one adapter, `python -m factory.adapter` ([adapter.md](../adapter.md)). A stage passes a prompt file, input files and a JSON schema, and gets back a validated JSON reply. The adapter allows only read tools by default, retries once on an invalid reply, and exits with a distinct code when the usage limit is hit. Today it drives the Claude Code CLI; a second adapter is `factory/adapter/fake.py`, which serves canned replies so every AI stage is tested offline. Adding another model means writing one more adapter. Prompts and rules are plain files in [prompts/](../../prompts) and [rules/](../../rules).

## What it caught

The factory is tested against two apps that were built to be insecure. Before a release, an acceptance workflow runs the candidate factory commit against both, and fails unless every planted flaw is found and the target's gate fails ([acceptance.md](../acceptance.md)). The latest acceptance run, [41195172634](https://github.com/AakashDadhich/security-factory/actions/runs/41195172634), passed for both targets on commit `f6064f8`. The tables below come from the recorded results of earlier runs of the same workflow.

**Vulnerable web app** ([factory-vuln-web](https://github.com/AakashDadhich/factory-vuln-web), acceptance run [41019054583](https://github.com/AakashDadhich/security-factory/actions/runs/41019054583); the target gate failed with 3 critical and 18 high findings):

| Planted flaw | Caught by | Finding |
|---|---|---|
| SQL injection | CodeQL, Semgrep | js/sql-injection (high) |
| Reflected XSS | CodeQL, Semgrep | js/reflected-xss (high) |
| Command injection | CodeQL, Semgrep | js/command-line-injection (critical) |
| `eval` on input | ESLint | security/detect-eval-with-expression (high) |
| Hardcoded API key | Gitleaks | generic-api-key (high) |
| Committed `.env` | secrets check | committed-env-file (high) |
| Old lodash | OSV-Scanner, Grype | CVE-2026-4800, CVE-2020-8203, CVE-2021-23337 (high) |
| Missing security headers | ZAP | CSP not set, anti-clickjacking, X-Content-Type-Options |
| Cookie without flags | ZAP | Cookie No HttpOnly Flag (low) |
| SQL injection (optional row) | AI review | review-cwe-89 (critical) |

Run [41047582825](https://github.com/AakashDadhich/security-factory/actions/runs/41047582825) added an authenticated XSS on `/account/notes` that ZAP reached only after logging in as a seeded test user.

**Vulnerable iOS app** ([factory-vuln-ios](https://github.com/AakashDadhich/factory-vuln-ios), acceptance run [41185475599](https://github.com/AakashDadhich/security-factory/actions/runs/41185475599); the target gate failed with 0 critical, 14 high, 4 medium, 1 low and 15 info findings):

| Planted flaw | Caught by | Finding |
|---|---|---|
| App Transport Security disabled | scripted Apple checks | ats-allows-arbitrary-loads (high) |
| No privacy manifest | scripted Apple checks | privacy-manifest-missing (high) |
| `get-task-allow` in Release | scripted Apple checks | get-task-allow-release (high) |
| Keychain item always accessible | scripted Apple checks | keychain-accessible-always (high) |
| Token in UserDefaults | Semgrep | userdefaults-sensitive-value (high) |
| MD5 for passwords | Semgrep merged with CodeQL | swift/weak-password-hashing (high) |
| ZIPFoundation 0.9.16 | OSV-Scanner | CVE-2023-39138 (high) |
| ATS allowed (optional row) | MobSF | mobsf-app-transport-security-allowsarbitraryloads-is-allowed (high) |

The same factory is also meant to stay quiet on clean apps. The clean web app run [41189428001](https://github.com/AakashDadhich/factory-test-web/actions/runs/41189428001) passed with 26 jobs, the clean macOS app run [41120571008](https://github.com/AakashDadhich/factory-test-macos/actions/runs/41120571008) passed with 0 critical and 0 high findings, and the clean iOS app run [41147346935](https://github.com/AakashDadhich/factory-test-ios/actions/runs/41147346935) passed with 4 medium MobSF findings that did not need suppressing.

Building the acceptance tests also exposed factory bugs, which is the point of having them. Examples: the review stage crashed when a branch had no base commit, a matcher failure was hidden because a workflow step had no `pipefail`, and an iOS entitlement key was missed because only the macOS spelling was known. Each was fixed with a test. A later fix (chunk 30.5) made acceptance test the release candidate instead of the already-released `v1`.

## Securing the factory itself

A pipeline that holds an AI token and a GitHub App key is itself a target. The controls, with evidence, are in [factory-security.md](factory-security.md). In short: least-privilege job permissions, actions pinned by commit SHA, a checksum-verified tool lock, AI jobs with read-only tools and no App key, an AST allowlist and a network-less container for AI-written threat models, a path filter on generated patches, an actor allowlist, no `pull_request_target`, and a fail-closed gate. The factory lints its own workflows with actionlint and zizmor in every self-test run, and the self-test passed on the latest commit ([41196404617](https://github.com/AakashDadhich/security-factory/actions/runs/41196404617)).

## Cost

Nothing beyond the existing Claude Pro subscription (P2). All repositories are public, which makes GitHub-hosted runners, macOS minutes, CodeQL and required checks free. The cost of that choice is the Pro usage window: AI stages fail cleanly when it is spent, and the gate fails closed until the owner re-runs after the reset.

## Limits and next steps

The honest list is in [limits.md](limits.md). The main ones: no dynamic analysis for iOS or macOS, thin Semgrep Swift coverage, AI output that varies between runs, and per-repo credentials because the factory lives on a personal account (D21). Next steps are the deferred items: Nuclei, TruffleHog, SOPS, Dagger, Model Context Protocol and a local Ollama adapter. A second, independent model behind the adapter would be the most useful test of the portability claim.

## What I would tell another builder

Keep the orchestrator boring. Make every stage write the same finding shape, so a gate can be small and strict. Test with apps that are wrong on purpose, and make the release depend on them. And treat the pipeline's own workflow files as code that needs the same scrutiny as the apps it checks.
