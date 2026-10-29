# Project record

Every project that runs the factory gets an orphan branch named `factory-record` in its own repo (D15). It has no shared history with the code. It holds the run history and the latest passing result, so a later run can see what changed.

The living plan and threat model are not here. They are committed with the code under `security/` (chunk 19).

## Layout

```
runs/
  20261029T064156Z-<run_id>.json   one per gate result, append-only
latest/
  sbom.cdx.json                    CycloneDX SBOM from the deps-sbom stage
  findings.json                    the merged gate report, suppressed findings included
  run-manifest.json                the setup job's run manifest
  sbom-diff.json                   added, removed and changed packages since the previous latest/
```

A `runs/` entry is named `<UTC timestamp>-<run_id>.json` and holds `run_id`, `mode`, `ref`, `commit`, `status` (`pass` or `fail`), `counts`, `blocking_fingerprints`, `iteration` and `issue`. It is written for every run, pass or fail, on any branch or pull request.

`latest/` is replaced as a whole, and only when the gate passed on a push to the default branch. A pull request or a failed gate never changes it. `sbom-diff.json` has the shape of `python -m factory.sbom diff` (`added`, `removed`, `changed`) and compares the new SBOM with the previous `latest/sbom.cdx.json`; the first time, everything is `added`.

## How it is written

The `record` job in `.github/workflows/factory.yml` runs after `gate` (skipped for fork pull requests, which have no secrets). It mints a short-lived GitHub App token for the current repo with `contents: write`, downloads the `gate`, `deps-sbom` and `setup` artifacts, and runs:

```
python -m factory.record write --repo <owner/name> --artifacts in --event <event> --ref <ref> --default-branch <name> --run-id <id> --commit <sha>
```

The commit is authored by the App bot with message `chore(record): <mode> run <run_id> <status>`. If the push is rejected because another run pushed first, the job fetches the branch, re-applies its changes on top and pushes again, up to 3 attempts. Files are either new or replaced whole, so this never conflicts.

The project stub ignores pushes to `factory-record` (`branches-ignore`), so writing the record never starts a run.

## How it is read

```
python -m factory.record read --repo <owner/name> --out <dir>
```

Copies `latest/` and the 10 newest `runs/` entries into `<dir>`, or creates an empty `<dir>` if the branch does not exist yet. The branch is public like the repo, so no token is needed.

- **Plan stage (chunk 16)** reads `latest/findings.json` and `latest/run-manifest.json` to see what the shipped project already has open or suppressed, and `sbom-diff.json` to see what the last change added.
- **Improvement loop (chunk 24)** walks `runs/` for repeated `blocking_fingerprints` across runs and joins them to `latest/findings.json` to find the rules that keep failing.
