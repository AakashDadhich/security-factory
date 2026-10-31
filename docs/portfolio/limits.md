# Limits

What the factory does not do, and where it is weaker than it looks. Decision numbers refer to [plan/decisions.md](../../plan/decisions.md).

## Coverage gaps

- **No iOS dynamic analysis.** MobSF dynamic analysis of an iOS app needs Corellium, which is paid, so the factory runs MobSF static analysis only (D12). Runtime behaviour such as certificate pinning, data left in memory or on disk, and jailbreak checks is not tested.
- **No macOS MobSF.** MobSF does not support macOS apps. macOS gets SwiftLint, CodeQL, Semgrep and the scripted checks (hardened runtime, sandbox, entitlements, privacy manifest) but no binary analysis tool.
- **Thin Semgrep Swift coverage.** The factory ships four custom Swift rules ([semgrep-rules/custom/swift](../../semgrep-rules/custom/swift)) on top of the community rules, which cover Swift much less than JavaScript. One known gap: the rule for accepting all certificates is excused by any trust evaluation call in the delegate, even if the result is ignored.
- **No dynamic testing of anything but web apps.** ZAP covers web apps. APIs without an OpenAPI file are found only by the spider.
- **Dev dependencies are not in the SBOM.** Syft omits them, so the SBOM diff and its note reflect runtime dependencies only.
- **Only a few app shapes were tested.** The acceptance targets are one Express app and one SwiftUI app. The factory has not been shown on, for example, a Python web service or an Android app, and does not claim to support them.

## AI behaviour

- **Non-determinism.** The same issue can give different plans, threat models and code on different runs. Schema checks, the AST allowlist, the patch filter and the gate limit the damage, but they do not make the output repeatable. In a live run the model named threat model elements loosely, so 5 of 8 touched elements did not match the model and were ignored ([PROGRESS.md notes on chunk 24](../../plan/PROGRESS.md)). In another, a fix attempt changed no files three times.
- **The reviewer is also a model.** The second-agent review uses the same model family as code generation, so shared blind spots are likely. It is a second look, not an independent audit.
- **Generated code is not run by the AI job.** That is a security choice, but it means the model cannot run tests while writing code. Tests run only in the project's own CI.
- **Findings from the AI stages are advisory in places.** Threat model findings are `info` and do not block the gate. Review findings can block, but the guard downgrades any that point outside the changed lines.

## Cost and capacity

- **Claude Pro usage limits (P2).** AI stages fail cleanly when the limit is hit (adapter exit 75). In check mode that fails the gate, so you re-run after the reset. Weekly acceptance runs and releases also spend allowance, and a limit hit during acceptance can fail the run for the wrong reason.
- **AI skipped on work-in-progress pushes (D18).** The threat model update and the review run only on pull requests and default-branch pushes. A push to a feature branch with no PR gets scanners and the gate but no AI review, and forks never get AI stages.
- **macOS capacity.** Free-plan accounts have 5 concurrent macOS jobs, and macOS runs can queue for 10 minutes or more. A macOS or iOS run takes roughly 12 to 25 minutes.

## Account and credentials

- **No organisation (D21).** The factory lives on a personal account, which has no account-wide secrets, variables or Actions policy. Every repository holds its own copy of the credentials and its own Actions allow list. Nothing defines them once, so repositories can drift. Rotation means re-running the setup loop in [setup-repos.md](../setup-repos.md) for every tagged repository. The decision says to revisit this at about 10 to 15 projects or when collaborators join.
- **`secrets: inherit` to the factory.** A project stub passes all of its secrets to the factory workflow. This is accepted because the workflow is the owner's own and pinned by tag, but it is broader than naming the two secrets.
- **Single maintainer.** One person writes, reviews and releases. Tags are not signed and no second approver exists.

## Release and testing limits

- **Acceptance YAML comes from `main`.** The vulnerable apps follow the candidate commit for the factory's scripts, but the reusable workflow file is loaded from `main` ([release.md](../release.md)). Releasing from the head of `main` keeps the two equal.
- **Acceptance can pass for a partly wrong reason.** It needs every expected finding and a failed target gate, so a target that also fails on a stage error can still pass. This was left unchanged on purpose.
- **Weak test targets can age.** The vulnerable apps pin old dependencies on purpose. A dependency scanner that changes its database could stop reporting a given CVE.

## Deferred items

These are decided as later, not rejected ([decisions.md](../../plan/decisions.md)):

- **Nuclei** for DAST. Its templates target CVEs in off-the-shelf products, not custom apps (D11).
- **TruffleHog** as a second secrets scanner, if Gitleaks gets noisy (D9).
- **SOPS with age** for secrets management in the owner's apps (D10).
- **Dagger** as orchestration glue on top of Make (D13).
- **Model Context Protocol** and **Ollama** (D14). The adapter interface leaves room for a local model, but only the Claude Code adapter exists.
