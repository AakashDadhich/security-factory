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
- a completed, successful `acceptance.yml` run,

each updated within the last 7 days. If either is missing the job fails before touching any tag, with a message such as `no successful acceptance run for <sha> in the last 7 days. Run the missing workflow on this commit, then release again.`

When both are present it creates the dated tag `v1.YYYYMMDD` (UTC) and moves `v1` to the commit by force. Tags are lightweight refs made through the API with the workflow's `contents: write` token, which exists only in this workflow. A second release on the same day for a different commit is refused (the dated tag would have to move); wait until the next day or release the same commit again.

## Rolling back

Move `v1` back to an older dated tag: `gh api -X PATCH repos/AakashDadhich/security-factory/git/refs/tags/v1 -f sha=<commit of v1.YYYYMMDD> -F force=true`. Projects pick it up on their next run.

## Limits to know about

- `acceptance` checks the vulnerable apps through their own stubs. Once those stubs call `@v1`, a run of `acceptance.yml` exercises the released `v1`, not the commit being released, so the acceptance run that counts for a new release is only meaningful when the vulnerable apps follow the commit under test. Until that is solved, treat a green acceptance run on a candidate as proof for `v1` only if you temporarily pointed the vulnerable stubs at `@main`.
- Only the owner can run the workflow (it needs write access to the factory repo).
