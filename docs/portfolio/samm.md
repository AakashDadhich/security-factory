# OWASP SAMM self-assessment

A lightweight self-assessment of the factory against [OWASP SAMM](https://owaspsamm.org/) (decision D1 deferred it to this page). It uses SAMM's 5 business functions and 3 practices each, scored 0 to 3. It scores the factory as a software project that is built and released, not the apps it checks. It is a single-person, self-scored review, so read it as a structured to-do list rather than an audit.

Scale used: 0 nothing in place, 1 started or ad hoc, 2 defined and repeatable, 3 measured and enforced at scale. A 3 is rare here because the factory has one owner and no usage metrics.

**Total: 31 of 45.** Strongest in Design and Verification. Weakest in Operations, which is expected for a pipeline that is not a hosted service.

## Governance

| Practice | Score | Evidence | One improvement |
|---|---|---|---|
| Strategy and metrics | 1 | Decisions and reasons are recorded in [plan/decisions.md](../../plan/decisions.md). Acceptance results are recorded per run ([acceptance.md](../acceptance.md)). No trend metrics. | Publish counts per run (findings by stage, time to green) from the `factory-record` history. |
| Policy and compliance | 2 | A written policy in [policy.yml](../../policy.yml), enforced by the gate; suppressions need a reason, approver and expiry ([pipeline.md](../pipeline.md)). Rules map to ASVS 5.0.0 ([rules.md](../rules.md)). | Map the gate policy to a named compliance framework, not just ASVS. |
| Education and guidance | 2 | Plain-text rules and prompts ([rules/](../../rules), [prompts/](../../prompts)), onboarding ([onboarding.md](../onboarding.md)), a project template. Written for one person. | Add a short secure-coding guide for contributors, so rules are readable outside the prompts. |

## Design

| Practice | Score | Evidence | One improvement |
|---|---|---|---|
| Threat assessment | 3 | STRIDE on every change, LINDDUN and attack trees by trigger, threat model as code and diffed on each change ([pipeline.md](../pipeline.md), [threats.schema.json](../../schemas/threats.schema.json)). This is the factory's design strength. The factory's own threat model is only informal, so treat the 3 as applying to the product, not to the factory. | Write a pytm model of the factory itself, using its own stage. |
| Security requirements | 3 | ASVS 5.0.0 data in [rules/asvs/](../../rules/asvs), level chosen per project by rule (D2), abuse case per feature, requirements checked by the review stage ([contracts.md](../contracts.md)). | Trace each requirement to the test that proves it. |
| Security architecture | 2 | Deterministic orchestrator with AI confined to stages, schema-checked contracts, adapter boundary ([adapter.md](../adapter.md)). Trust boundaries are written in [factory-security.md](factory-security.md) but not drawn. | Add a trust boundary diagram to [diagrams.md](diagrams.md). |

## Implementation

| Practice | Score | Evidence | One improvement |
|---|---|---|---|
| Secure build | 3 | Pinned actions by SHA, checksum-verified tool lock ([versions.lock](../../tools/versions.lock)), hash-pinned Python packages, SBOM per run, workflows linted by actionlint and zizmor in [selftest.yml](../../.github/workflows/selftest.yml). | Sign the `v1` tag and publish an SBOM for the factory itself. |
| Secure deployment | 2 | Releases need a green self-test and acceptance run on the exact commit ([release.md](../release.md)); rollback documented. Tags are not signed and one maintainer approves. | Require a second approver or signed tags, once there is another maintainer. |
| Defect management | 2 | Findings share one schema with stable fingerprints, a merged report, and a bounded fix loop ending in `factory:needs-human`. Factory bugs found by acceptance are logged in [PROGRESS.md](../../plan/PROGRESS.md). | Track factory defects as GitHub issues with severity, not only in notes. |

## Verification

| Practice | Score | Evidence | One improvement |
|---|---|---|---|
| Architecture assessment | 1 | Automated security review on each change to the factory, which found several real bypasses during development, but there is no scheduled architecture review. | Review the factory against its own threat model each quarter. |
| Requirements-driven testing | 3 | Unit tests run in every self-test (1233 passed, 8 skipped on release commit `90b1867`, run [41188167458](https://github.com/AakashDadhich/security-factory/actions/runs/41188167458)). Tests guard security properties, such as where the App key may appear and that no workflow uses `pull_request_target`. | Report mutation or coverage numbers to see what the tests do not cover. |
| Security testing | 3 | The vulnerable web and iOS apps with expected-findings files, run weekly and before each release ([acceptance.md](../acceptance.md)); clean apps must stay clean. | Add a vulnerable macOS app, which has no acceptance target yet. |

## Operations

| Practice | Score | Evidence | One improvement |
|---|---|---|---|
| Incident management | 1 | Secret rotation is one loop ([setup-repos.md](../setup-repos.md)), and `SECURITY.md` ships in the project template. No documented response plan for a leaked token or compromised release. | Write a short runbook: revoke, rotate, move `v1` back, review run logs. |
| Environment management | 2 | Repo hardening applied by one loop to every tagged repo (read-only token, push protection, Actions allow list). Per-repo copies can drift if the loop is skipped (D21). | Add a scheduled job that reports drift between repos and the loop's expected state. |
| Operational management | 1 | Runner limits are documented ([runners.md](../runners.md)); Dependabot keeps pins current. No alerting on a failed weekly acceptance run beyond GitHub's default email. | Open an issue automatically when the weekly acceptance run fails. |

## Totals

| Function | Score |
|---|---|
| Governance | 5 of 9 |
| Design | 8 of 9 |
| Implementation | 7 of 9 |
| Verification | 7 of 9 |
| Operations | 4 of 9 |
