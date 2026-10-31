# Stages

One short section per stage. Full detail is in [pipeline.md](../pipeline.md); the stage list for each platform and mode is in [factory/stage_matrix.py](../../factory/stage_matrix.py). Every stage writes `out/<stage>/findings.json` in the shape defined by [schemas/finding.schema.json](../../schemas/finding.schema.json) ([contracts.md](../contracts.md)). The gate blocks on `critical` and `high` findings ([policy.yml](../../policy.yml)), and a project can only tighten that. Beyond the findings, a missing, failed or invalidly skipped stage is itself a critical, unsuppressible finding.

## Control jobs

| Job | Purpose |
|---|---|
| `authorize` | In spec, change and fix modes, checks the label actor and issue author against `FACTORY_ALLOWED_ACTORS`. A refusal stops every model call. |
| `setup` | Validates `.factory.yml` and writes the run manifest ([schemas/run-manifest.schema.json](../../schemas/run-manifest.schema.json)). |
| `ai-eligible` | Check mode only. Decides whether the AI stages run: not on forks, not on work-in-progress pushes, not without the token (D18). |

## AI stages

### plan
- **Purpose:** turn an issue into features, requirements, abuse cases and an ASVS level.
- **Tool:** the model adapter, prompt [prompts/plan.md](../../prompts/plan.md), schema [plan.schema.json](../../schemas/plan.schema.json). Change mode uses [plan-change.md](../../prompts/plan-change.md).
- **Input:** the issue text, `.factory.yml`, and in change mode the committed `security/plan.json` and the project record.
- **Output:** `plan.json`, a plan comment on the issue.
- **Blocks the gate:** only by failing (a feature without an abuse case exits 2). Findings are empty.

### threat-model
- **Purpose:** keep a diffable threat model as code.
- **Tool:** pytm, plus STRIDE always, LINDDUN when the plan flags personal data, attack trees for high-risk features (D3, D4). The AI writes `tm.py`, which passes an AST allowlist and runs in a network-less container.
- **Input:** the plan (spec, change) or the diff (check), and the previous `security/` files.
- **Output:** `tm.py`, `threats.json`, `dfd.dot`, attack trees as Mermaid, one `info` finding per open threat.
- **Blocks the gate:** no, its findings are `info`. A failure (including a usage limit) fails the stage and so the gate.

### codegen-ai and codegen-commit
- **Purpose:** write the code, then commit it without trusting the first job.
- **Tool:** the adapter with Read, Grep, Glob, Edit and Write only, then pre-commit hooks that call Semgrep and Gitleaks.
- **Input:** plan, threat model, rendered rules (`CLAUDE.md`, `AGENTS.md`).
- **Output:** a patch, then one bot commit on `factory/<issue>`.
- **Blocks the gate:** a patch policy or pre-commit refusal after two retries is a `high` finding (`patch-policy-blocked`, `precommit-blocked`).

### review
- **Purpose:** an independent second agent reads the diff against the ASVS checklist and open threats.
- **Tool:** the adapter, [prompts/security-review.md](../../prompts/security-review.md).
- **Input:** the diff, the checklist, open threats.
- **Output:** findings with source `ai-review`. A finding outside the changed hunks is downgraded to `info`, and low confidence caps at `medium`.
- **Blocks the gate:** high and critical review findings block like scanner findings (D19).

## Scanners

### secrets
- **Purpose:** find committed secrets in the full history.
- **Tool:** Gitleaks, plus a check for tracked `.env` files.
- **Input:** the repository with full history.
- **Output:** `gitleaks.sarif`, findings (always `high`).
- **Blocks the gate:** any secret or committed `.env`.

### sast-semgrep
- **Purpose:** pattern-based static analysis on every platform.
- **Tool:** Semgrep Community Edition with pinned community rules and the factory's custom rules in [semgrep-rules/](../../semgrep-rules).
- **Input:** source.
- **Output:** `semgrep.sarif`, findings.
- **Blocks the gate:** high and critical.

### sast-codeql
- **Purpose:** data-flow analysis for JavaScript and TypeScript.
- **Tool:** CodeQL, `security-extended`.
- **Input:** source on Linux.
- **Output:** `javascript.sarif`, findings, and an upload to code scanning.
- **Blocks the gate:** high and critical.

### sast-eslint
- **Purpose:** web-specific lint rules for risky APIs.
- **Tool:** ESLint with `eslint-plugin-security` and `eslint-plugin-no-unsanitized`, using the factory's config only.
- **Input:** source.
- **Output:** SARIF, findings. Errors are `medium`; `eval` and unsanitized HTML sinks are `high`.
- **Blocks the gate:** the escalated rules.

### deps-sbom
- **Purpose:** known-vulnerable dependencies and a software bill of materials.
- **Tool:** OSV-Scanner, Syft (CycloneDX) and Grype. Results for the same vulnerability merge (D7, D8).
- **Input:** lockfiles, `Package.resolved`.
- **Output:** `sbom.cdx.json`, `osv-scanner.sarif`, `grype.sarif`, findings.
- **Blocks the gate:** high and critical vulnerabilities.

### dast-web
- **Purpose:** test the running web app.
- **Tool:** OWASP ZAP in a container, spider, OpenAPI import and an active scan, optionally logged in ([pipeline.md](../pipeline.md)). The app runs in a throwaway container on an internal network.
- **Input:** the project's Dockerfile, `.factory.yml` and optional OpenAPI file.
- **Output:** ZAP report, `sites.json`, findings.
- **Blocks the gate:** high and critical alerts. A target that never becomes healthy fails the stage.

### sast-swiftlint
- **Purpose:** Swift lint with security-flavoured custom rules.
- **Tool:** SwiftLint, [tools/swiftlint/.swiftlint.yml](../../tools/swiftlint/.swiftlint.yml). Only two custom rules are `high`; the rest are `low`.
- **Input:** Swift source on `macos-15`.
- **Output:** SARIF, findings.
- **Blocks the gate:** the two custom rules.

### codeql-swift-analyze and sast-codeql-swift
- **Purpose:** data-flow analysis for Swift.
- **Tool:** CodeQL on `macos-15` with a traced build, then a Linux job that converts the SARIF.
- **Input:** the Xcode project.
- **Output:** `swift.sarif`, findings.
- **Blocks the gate:** high and critical.

### apple-build and apple-checks
- **Purpose:** prove the app builds, then inspect the built artifact.
- **Tool:** XcodeGen and `xcodebuild` (ad-hoc signed macOS app, unsigned iOS `.ipa`), then scripted checks with `plistlib` and `codesign`.
- **Input:** the project spec and source.
- **Output:** the built app, findings for ATS, privacy manifests, entitlements, hardened runtime, sandbox and Keychain accessibility.
- **Blocks the gate:** the rules marked `high` (for example `ats-allows-arbitrary-loads`, `get-task-allow-release`).

### mobsf
- **Purpose:** static analysis of the iOS binary and its configuration.
- **Tool:** MobSF 4.6.2 in a digest-pinned container, driven over its REST API with a per-run key (D12).
- **Input:** `app.ipa`.
- **Output:** `mobsf-report.json`, findings (`high`, `warning` as `medium`, `info`).
- **Blocks the gate:** `high` findings.

## Decision and bookkeeping

| Job | Purpose |
|---|---|
| `gate` | Merges and de-duplicates findings, applies the policy and unexpired suppressions, writes `report.md`, `gate-result.json` and `merged.sarif`. Fails closed. |
| `next-step` | After a gate in spec, change or fix mode, dispatches the next fix round, stops at the cap with `factory:needs-human`, or reports success with the threat model diff. |
| `record` | After the gate, writes the run to the `factory-record` branch using the GitHub App key. It is the only job besides `codegen-commit` and `next-step` that sees that key, and no AI job sees it. |
