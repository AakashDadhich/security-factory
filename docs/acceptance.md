# Vulnerable web acceptance test

`AakashDadhich/factory-vuln-web` is a deliberately vulnerable Express app. It lives in its own public repo and runs only in CI. It must never be deployed. The factory runs on it in check mode, and `acceptance.yml` then proves that each planted flaw was caught by the stage expected to catch it and that the gate failed.

## Running it

```bash
gh workflow run acceptance.yml --repo AakashDadhich/security-factory
```

The workflow also runs every Monday. It mints an App token for `factory-vuln-web` (the App needs `actions: write` there), dispatches that repo's `factory.yml` stub on `main`, polls every 30 seconds for up to 60 minutes (`python -m factory.acceptance_run`), then runs `python -m factory.acceptance`. The job is green only when the gate failed and every non-optional expectation matched. The table is uploaded as artifact `acceptance` (`acceptance.md`, `acceptance.json`) and shown in the job summary.

## `expected-findings.yml`

A list in the vulnerable repo. Each entry:

| Field | Meaning |
|---|---|
| `id` | unique name |
| `stage` | a stage name, or a list of acceptable stages |
| `rule_id` | optional regex (`re.search`) on the finding's rule id |
| `cwe` | optional CWE string or list, e.g. `CWE-89` |
| `path` | optional regex on the finding path (or URL for DAST findings) |
| `min_severity` | the finding must be at least this severe |
| `optional` | `true` for checks that depend on AI; a miss does not fail |

An entry needs `rule_id` or `cwe`; either is enough to match. A finding counts when one of the stages it merged from is in `stage`, and suppressed findings never count. The matcher reads `report.json` and `gate-result.json` from the run's `gate` artifact.

## Check-mode event

The stub triggers the run with `workflow_dispatch` on `main`. Check mode treats that as a default-branch run, so the AI stages (`threat-model`, `review`) run on it and use the owner's Claude allowance. The review expectation is still optional because the model is non-deterministic. With no `before` commit, the review job diffs against the empty tree.
