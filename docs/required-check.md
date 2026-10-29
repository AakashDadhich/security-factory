# Making the gate a required check

The stub in each project repo calls the factory workflow from a job named `factory`, and the factory's last job is `gate`, so GitHub reports the check as `factory / gate`. A branch ruleset on the default branch that requires it stops merges while the gate is red.

Public repos can use rulesets for free (P1). This is a GitHub settings change, so do it per repo and only after the check has run at least once on the default branch.

## Steps in the web UI

1. Repo, Settings, Rules, Rulesets, New ruleset, New branch ruleset.
2. Name: `factory-gate`. Enforcement status: Active.
3. Target branches: Add target, Include default branch.
4. Turn on "Require status checks to pass". Add the check `factory / gate`. Leave "Require branches to be up to date" off for now.
5. Create.

## Steps with the CLI

Replace `REPO` with `owner/name`.

```bash
cat > ruleset.json <<'JSON'
{
  "name": "factory-gate",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "rules": [
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [{"context": "factory / gate"}]
      }
    }
  ]
}
JSON
gh api -X POST repos/REPO/rulesets --input ruleset.json
```

Check it:

```bash
gh api repos/REPO/rulesets --jq '.[] | {id, name, enforcement}'
gh api repos/REPO/rulesets/RULESET_ID --jq '.rules[] | select(.type == "required_status_checks") | .parameters.required_status_checks'
```

## Notes

- The bot never pushes to the default branch (P4), so a required check does not block factory work. Pushes straight to the default branch by the owner are also blocked until the check passes on a PR; that is the point.
- If the check name changes (for example the stub's job is renamed), the ruleset keeps waiting for the old name and merges hang. Update the ruleset with the new name.
- To bypass in an emergency, add the repository admin role as a bypass actor rather than turning enforcement off.
