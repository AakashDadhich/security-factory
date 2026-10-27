# Build plan index

32 chunks. Each chunk file is self-contained: give a fresh agent the starter prompt (bottom of this file) with one chunk file plus [PROGRESS.md](PROGRESS.md). Live status is tracked in PROGRESS.md; the Status column here is the starting value.

Sizes: S = under 1 hour of agent session, M = 1 to 2 hours, L = 2 to 3 hours.

| # | Chunk | Depends on | Can run in parallel with | Size | Status |
|---|---|---|---|---|---|
| 00 | [Accounts and repo setup](00-accounts-and-repo-setup.md) | none | none | S | todo |
| 01 | [Factory skeleton](01-factory-skeleton.md) | 00 | none | M | todo |
| 02 | [Pinned tool installer](02-pinned-tool-installer.md) | 01 | 03, 05 | M | todo |
| 03 | [Data contracts](03-data-contracts.md) | 01 | 02, 04, 05 | M | todo |
| 04 | [Model adapter](04-model-adapter.md) | 01, 02 | 03, 05 | M | todo |
| 05 | [Web test project](05-web-test-project.md) | 00 | 02, 03, 04 | S | todo |
| 06 | [Walking skeleton](06-walking-skeleton.md) | 02, 03, 04, 05 | none | M | todo |
| 07 | [Secrets stage](07-secrets-stage.md) | 06 | 08, 09, 10, 12, 15 | S | todo |
| 08 | [SAST: Semgrep](08-sast-semgrep.md) | 06 | 07, 09, 10, 12, 15 | M | todo |
| 09 | [SAST: CodeQL and ESLint (web)](09-sast-codeql-eslint-web.md) | 06 | 07, 08, 10, 12, 15 | M | todo |
| 10 | [Dependencies and SBOM](10-deps-and-sbom.md) | 06 | 07, 08, 09, 12, 15 | M | todo |
| 11 | [Gate and report](11-gate-and-report.md) | 07, 08, 09, 10 | 12, 13, 15 | M | todo |
| 12 | [DAST: ZAP baseline](12-dast-zap-baseline.md) | 06 | 07 to 11, 15 | M | todo |
| 13 | [DAST: ZAP active scan and OpenAPI](13-dast-zap-active-openapi.md) | 12 | 11, 14, 15 | M | todo |
| 14 | [Project record](14-project-record.md) | 11 | 13, 15 | M | todo |
| 15 | [Security rules and renderer](15-security-rules-and-renderer.md) | 01 | 02 to 14 | M | todo |
| 16 | [Clarify and plan stage](16-clarify-plan-stage.md) | 06, 14 | 15 | M | todo |
| 17 | [Threat model: pytm and STRIDE](17-threat-model-pytm-stride.md) | 16 | none | L | todo |
| 18 | [Threat model: LINDDUN and attack trees](18-threat-model-linddun-attacktrees.md) | 17 | 19 | M | todo |
| 19 | [Secure code generation](19-secure-codegen-stage.md) | 15, 17 | 18 | L | todo |
| 20 | [Second-agent security review](20-second-agent-review.md) | 19 | none | M | todo |
| 21 | [Fix loop](21-fix-loop.md) | 11, 20 | 22 | M | todo |
| 22 | [Check mode wiring](22-check-mode-wiring.md) | 11, 14, 18, 20 | 21 | M | todo |
| 23 | [Vulnerable web app acceptance test](23-vulnerable-web-acceptance.md) | 13, 21, 22 | none | M | todo |
| 24 | [Improvement loop](24-improvement-loop.md) | 21, 22 | 25, 26 | M | todo |
| 25 | [ZAP authenticated scanning](25-zap-authenticated-scan.md) | 23 | 24, 26 | M | todo |
| 26 | [macOS build and SAST](26-macos-build-and-sast.md) | 08, 10, 11 | 24, 25 | L | todo |
| 27 | [Apple scripted checks](27-apple-scripted-checks.md) | 26 | 28 | M | todo |
| 28 | [iOS build and MobSF](28-ios-build-and-mobsf.md) | 26 | 27 | L | todo |
| 29 | [Apple vulnerable app acceptance test](29-apple-vuln-acceptance.md) | 27, 28 | none | S | todo |
| 30 | [Project template and v1 release](30-template-and-release.md) | 23, 29 | none | S | todo |
| 31 | [Portfolio documentation](31-portfolio-docs.md) | 00 to 30 | none | M | todo |

## Parallel groups

"Parallel" means neither chunk needs the other's output. Most stage chunks add a job to the same file (`.github/workflows/factory.yml`), so run parallel chunks in separate git branches or worktrees and merge them one at a time. Running them one after another in number order is always safe.

- After 01: **02, 03, 05** (05 only needs 00). 04 starts once 02 is done, alongside 03 and 05.
- After 06: **07, 08, 09, 10, 12**, and 15 at any time after 01.
- After 11: **13, 14** (13 needs 12).
- After 20: **21, 22**.
- After 22 and 21: **24, 25, 26** (25 needs 23).
- After 26: **27, 28**.

## Critical path

00 → 01 → 02 → 04 → 06 → 10 → 11 → 14 → 16 → 17 → 19 → 20 → 22 → 23 → 30 → 31 (the Apple branch 26 → 28 → 29 must also finish before 30).

## Starter prompt

```
You are building one chunk of my Security Software Factory. Read only these two files first:
1. plan/PROGRESS.md
2. plan/NN-<slug>.md
Do not read other chunk files or the design document. Confirm the chunk's dependencies are marked done in PROGRESS.md; if not, stop and tell me. Use only the tools named in the chunk's Background (they come from decisions.md). Do the Tasks, leave the Outputs committed in small Conventional Commits, run every Done-when check and show me the results, then update PROGRESS.md (status, next up, notes, log). Ask before pushing.
```
