# Data contracts

Every stage hands the next one a predictable file. Findings are JSON, raw scanner output is SARIF 2.1.0, and SBOMs are CycloneDX JSON (D8). The schemas live in `schemas/` and use JSON Schema 2020-12.

## Stage output: `out/<stage>/`

Each stage writes into its own folder:

| File | When |
|---|---|
| `findings.json` | Always. An array matching `schemas/findings.schema.json`. An empty array means the stage ran and found nothing. |
| `*.sarif` | When the tool emits SARIF 2.1.0. Kept raw, as the tool wrote it. |
| `*.cdx.json` | When the stage produces an SBOM (CycloneDX JSON). |

The job uploads `out/<stage>/` as an artifact named exactly `<stage>` (for example `secrets`, `sast-semgrep`). Stage names are lowercase letters, digits and hyphens.

## `finding.schema.json` and `findings.schema.json`

One finding has exactly these fields, all required, no others allowed:

| Field | Meaning |
|---|---|
| `id` | `<stage>:<fingerprint>` |
| `stage` | Stage that produced it |
| `tool` | Tool or model that produced it |
| `source` | `scanner`, `ai-review`, `ai-threat-model` or `check` |
| `rule_id` | The tool's rule or check id |
| `title` | One line |
| `severity` | `critical`, `high`, `medium`, `low` or `info` |
| `location` | `{path, start_line, end_line}` (lines may be `null`) or `{url, method}` |
| `cwe` | List like `["CWE-89"]`, may be empty |
| `description` | What was found |
| `remediation` | How to fix it, may be empty |
| `fingerprint` | Stable SHA-256, see below |

AI findings use the same shape (`source: ai-review` or `ai-threat-model`) and are judged by the gate like any other (D19).

**Fingerprint.** SHA-256 of the JSON array `[tool, rule_id, path, start_line]` for file locations, or `[tool, rule_id, url_path, METHOD]` for URL locations. Paths are normalised first (URL-decoded, `\` to `/`, leading `./` and `file://` removed). URL locations use only the URL path, so the host, port and query string don't change it. The same issue reported by the same tool on the same line gets the same fingerprint on every run. Moving the code to another line changes it.

`factory/findings.py` provides `make_finding(**fields)` (fills in `id` and `fingerprint`), `fingerprint(tool, rule_id, location)`, `validate(list)`, `load(path)` and `write(path, list)`. `validate` also checks that every `id` and `fingerprint` match their fields and that no `id` repeats.

## `run-manifest.schema.json`

What one pipeline run did:

| Field | Meaning |
|---|---|
| `run_id` | Unique run id |
| `mode` | `spec`, `check`, `fix` or `change` |
| `platform` | `web`, `macos` or `ios` |
| `iteration` | Fix-loop round, 0 to 2 |
| `issue` | GitHub issue number, or `null` |
| `repo` | `owner/name` |
| `commit_sha` | 40-character commit SHA |
| `factory_ref` | Factory ref the run used |
| `asvs_level` | 1, 2 or 3 |
| `stages` | `[{name, status}]`, status is `pending`, `running`, `success`, `failure` or `skipped` |
| `tool_versions` | Map of tool name to version string |

Validate one with `factory.findings.validator("run-manifest.schema.json")`.

## SARIF to findings

```
python -m factory.sarif <file.sarif> --stage <stage> --tool <tool> [--out out/<stage>/findings.json]
```

Without `--out` it prints the findings. Results with `kind` `pass` or `notApplicable` are skipped. Results with the same fingerprint are merged, keeping the highest severity. Rules are looked up in the driver and in `tool.extensions` (CodeQL query packs).

**Severity map.** If the result or its rule has `properties.security-severity`, use the score:

| Score | Severity |
|---|---|
| >= 9.0 | critical |
| >= 7.0 | high |
| >= 4.0 | medium |
| > 0 | low |
| 0 | info |

Otherwise use the SARIF `level` (the result's, else the rule's `defaultConfiguration.level`, else `warning` as SARIF specifies):

| Level | Severity |
|---|---|
| error | high |
| warning | medium |
| note | low |
| none | info |

Gitleaks sets no level, so its findings start as `medium`. A stage may raise that itself.

**CWE.** Read from rule and result `properties.tags`: both `CWE-89: ...` (Semgrep) and `external/cwe/cwe-089` (CodeQL) become `CWE-89`.

## SBOM helpers

```
python -m factory.sbom components <bom.cdx.json>
python -m factory.sbom diff <old.cdx.json> <new.cdx.json>
```

`components` lists `{name, version, purl}` for every component, nested ones included, but not `metadata.component` (the app itself). A `group` is prefixed to the name (`@types/node`). `diff` matches packages by purl without its version, qualifiers and subpath (or by name when there is no purl) and returns `added`, `removed` and `changed` (`{name, old_versions, new_versions}`). Versions are lists because one package can appear at several versions.
