# Releasing the factory (v1)

Projects call the factory at `@v1` and check it out with `factory-ref: v1` (D17). They pick up a change only when the owner moves `v1`, and the owner moves it only after the self-test and the acceptance tests pass on the exact commit.

## Cutting a release

1. Push the commit to `main` and wait for `selftest` to go green on it.
2. Run `acceptance` on the same commit and wait for it to go green (`gh workflow run acceptance.yml --repo AakashDadhich/security-factory`, then `gh run watch`). It dispatches the factory on `factory-vuln-web` and `factory-vuln-ios` and checks every planted flaw is caught, so it uses the Claude allowance. Exit code 75 from the adapter means the usage limit was hit: re-run after the reset.
3. Run the release: `gh workflow run release.yml --repo AakashDadhich/security-factory -f confirm=v1`, then `gh run watch`.

The workflow refuses to run anywhere except `main`, and the `confirm` input must be exactly `v1`.

## What `release.yml` checks

`python -m factory.release release` uses the API to look for runs whose `head_sha` is the commit being released:

- a completed, successful `selftest.yml` run, and
- a completed, successful `acceptance.yml` run whose result shows that both vulnerable apps checked out the factory at exactly that commit,

each updated within the last 7 days. For the acceptance run it downloads the artifacts `acceptance-factory-vuln-web` and `acceptance-factory-vuln-ios` (`acceptance.json`) and requires `ok` and `factory.commit` to equal the release commit for both. The newest run that qualifies is used. If something is missing the job fails before touching any tag, with a message such as `no successful acceptance run for <sha> in the last 7 days.` or `no acceptance run tested <sha> (acceptance run N tested factory commit <other> (ref v1) on factory-vuln-web, not <sha>)`, followed by `Run the missing workflow on this commit, then release again.`

When both are present it creates the dated tag `v1.YYYYMMDD` (UTC) and moves `v1` to the commit by force. Tags are lightweight refs made through the API with the workflow's `contents: write` token, which exists only in this workflow. A second release on the same day for a different commit is refused (the dated tag would have to move); wait until the next day or release the same commit again.

## Rolling back

Move `v1` back to an older dated tag: `gh api -X PATCH repos/AakashDadhich/security-factory/git/refs/tags/v1 -f sha=<commit of v1.YYYYMMDD> -F force=true`. Projects pick it up on their next run.

## Limits to know about

- The two vulnerable apps' stubs call the factory workflow at `@main` and take `factory-ref` from a `workflow_dispatch` input (default `main`). `acceptance.yml` dispatches each with `factory-ref` set to its own `github.sha`, so the factory scripts and actions under `.factory/` are the candidate commit. The target run's `run-manifest.json` records the resolved commit (`factory_commit`), `factory.acceptance` copies it into `acceptance.json` and fails when it differs from the acceptance run's commit, and the release check requires the same.
- Remaining limit: the reusable workflow YAML itself (`factory.yml`) is loaded from the stub's `@main`, not from the passed ref; only `.factory/` follows `factory-ref`. If the candidate commit is not the head of `main` when acceptance runs, the YAML under test is `main`'s. The check above detects a mismatch of the checked-out factory, and releasing from the head of `main` (which `release.yml` enforces by running only on `main`) keeps the two the same.
- Push/PR runs on the vulnerable apps use `main` for both the workflow and `.factory/`, so they follow the factory's head, not `v1`. The clean test projects and the template stay on `@v1`.
- Only the owner can run the workflow (it needs write access to the factory repo).
