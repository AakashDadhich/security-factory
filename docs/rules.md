# Security rules and renderer

The factory's security rules are plain Markdown files in `rules/`, each with YAML front matter (`id`, `title`, `applies_to`: any of `web`, `macos`, `ios`, `all`). `CLAUDE.md` and `AGENTS.md` are generated from them; never edit a generated file by hand.

| File | Applies to | Content |
|---|---|---|
| `rules/base.md` | all | OWASP Top 10:2025 as do/don't rules |
| `rules/secure-defaults.md` | all | parameterised queries, output encoding, input allowlists, least privilege, vetted crypto, no secrets in code |
| `rules/web.md` | web | headers, CSRF, session cookies, rate limits, no stack traces |
| `rules/apple.md` | macos, ios | Keychain, ATS, entitlements, sandbox, privacy manifest, CryptoKit |
| `rules/asvs/asvs.json` | all | ASVS 5.0.0 requirements (`id`, `chapter`, `level`, `text`), see `rules/asvs/SOURCE.md` |

## Render

```
python -m factory.rules render --platform <web|macos|ios> --asvs-level <1|2|3> \
    [--threats security/threats.json] --target <claude|agents> --out <file>
python -m factory.rules checklist --asvs-level <1|2|3> --out <file>
```

Output order: header comment, Base, Secure defaults, platform rules, `ASVS L1+...+Ln` grouped by chapter, then (only when `--threats` is given) `Project-specific mitigations`. The `claude` and `agents` targets differ only in the first line. Output is sorted and has no timestamps, so the same inputs give the same bytes. `make rules PLATFORM=web ASVS_LEVEL=2` writes both files to `out/rules/`.

## threats.json shape accepted

A list, or an object with a `threats` list. Each threat has `id`, optional `title`, optional `status` (threats with status `closed`, `mitigated`, `resolved`, `accepted` or `rejected` are skipped, anything else is open), and `mitigations`: strings, or objects with `text`, optional `id` (default `<threat id>-M<n>`) and `asvs` (list of requirement ids; `asvs_refs` also works). Threats with no mitigations are skipped. The threat model chunks should write this shape.

## Checklist

`checklist` writes a JSON array of `{id, chapter, level, text}` for every requirement up to the level, for the second-agent review.
