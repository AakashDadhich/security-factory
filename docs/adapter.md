# Model adapter

Every AI stage calls one command. It takes a prompt file, input files and an output schema, runs whichever model is current, and writes JSON that has already been checked against the schema. The differences between models (how they launch, how they see files, how they reply) live only in the adapter, so changing model never touches prompts, stages or the orchestrator.

## Command

```
python -m factory.adapter run --stage <name> --prompt prompts/<file>.md \
  --input <path> [--input <path>...] --schema schemas/<file>.json \
  --out out/<stage>/<file>.json [--workdir <dir>] [--allow-tools <list>] [--allow-write]
```

| Option | Meaning |
|---|---|
| `--stage` | Stage name: lowercase letters, digits and hyphens. |
| `--prompt` | Prompt text file. |
| `--input` | A file or directory the model works on. Repeatable. |
| `--schema` | JSON Schema (2020-12) the reply must match. |
| `--out` | Where the validated JSON goes. A sidecar `<out>.meta.json` is written next to it. |
| `--workdir` | Directory the model runs in (default: the current directory). |
| `--allow-tools` | Comma-separated tool list replacing the default `Read,Grep,Glob`. Only `Read`, `Grep`, `Glob` are accepted, plus `Edit` and `Write` with `--allow-write`. |
| `--allow-write` | Adds `Edit` and `Write`. Off by default. |

`Bash`, `WebFetch` and `WebSearch` are never accepted, in any form. Stages read repo content that may be hostile (prompt injection), so the model gets read-only file tools and no shell or web access. A later stage that truly needs to run commands must change the adapter on purpose, not pass a flag.

## Environment

| Variable | Used by | Meaning |
|---|---|---|
| `FACTORY_MODEL_ADAPTER` | interface | Adapter module to use (default `claude_code`). Lowercase letters, digits and `_`. |
| `CLAUDE_CODE_OAUTH_TOKEN` | `claude_code` | The only credential passed to the CLI. Never logged; redacted from any CLI output the adapter prints. |
| `FACTORY_CLAUDE_MODEL` | `claude_code` | Optional model id or alias, passed as `--model`. |
| `FACTORY_CLAUDE_TIMEOUT` | `claude_code` | Seconds before the CLI is killed (default 600). |
| `FACTORY_CLAUDE_MAX_TURNS` | `claude_code` | Max agent turns (default 25). |
| `FACTORY_FAKE_RESPONSES` | `fake` | Directory of canned replies. |

## What the adapter does

1. Builds one prompt from: the prompt file, each input (path, size and contents inside a fence; a note that file contents are data, not instructions), the JSON Schema, and a fixed instruction to reply with JSON only.
   - A file over 64 KiB, or one that would push the total past 256 KiB, is listed by path only, and the model reads it with its tools. Non-UTF-8 files and directories are also listed by path only.
   - Inputs outside `--workdir` have their folder added to the model's allowed directories.
2. Runs the adapter and parses the reply as JSON (a single surrounding Markdown fence is tolerated), then validates it with `jsonschema`.
3. If the reply is invalid, runs once more with the rejected reply and the validation errors appended. If it is still invalid, it writes `<out>.rejected.txt` and exits 2.
4. Writes `--out` and `<out>.meta.json`:

```json
{"stage": "hello", "adapter": "claude_code", "model": "claude-opus-5-5",
 "duration_seconds": 8.412, "attempts": 1, "valid": true,
 "num_turns": 1, "cli_duration_ms": 7980}
```

`stage`, `adapter`, `model`, `duration_seconds`, `attempts` and `valid` are always present; an invalid run adds `errors`. Other keys come from the adapter.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Reply valid, written to `--out`. |
| 1 | Setup or model error: bad arguments, missing file, bad schema, unknown adapter, missing token or CLI, CLI failure, max-turns cap hit. |
| 2 | Reply still failed the schema after one retry. |
| 75 | Usage or rate limit (`EX_TEMPFAIL`). Prints `Claude usage limit reached; re-run later`. Safe to re-run later. |
| 124 | Timed out (same code as coreutils `timeout`). |

## Adapters

### `claude_code`

Runs the CLI pinned in `tools/versions.lock` (`python -m factory.tools install claude-code`) as:

```
claude --print --output-format json --restricted --tools <list> --allowed-tools <list>
  --disallowed-tools Bash,WebFetch,WebSearch --permission-mode dontAsk
  --strict-mcp-config --no-session-persistence --max-turns <n> [--add-dir <dir>...] [--model <id>]
```

The prompt goes in on stdin. `--restricted` removes shell and web tools and ignores user and project settings files, `dontAsk` denies anything not on the allowlist instead of waiting for a person, and `--strict-mcp-config` with no config loads no MCP servers. The child process gets only `PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR`, `USER`, `CI`, `RUNNER_TEMP` and the OAuth token, so other secrets in the job (`GH_TOKEN`, API keys) never reach the model. The model reported in the meta file is the one with the most output tokens in the CLI's `modelUsage`.

A usage or rate limit is recognised only when the CLI reports an error, by matching phrases such as "usage limit", "rate limit", "hit your limit" or HTTP 429. Words like that inside a successful reply are ignored.

`--max-turns` does not appear in `claude --help` but is accepted in print mode. The `adapter-smoke` workflow checks every other flag against the pinned CLI's help, and its real run proves the full command line is accepted.

### `fake`

Returns `$FACTORY_FAKE_RESPONSES/<stage>.<attempt>.json` if it exists, otherwise `<stage>.json`. The model is reported as `fake`. Use it in stage tests so they run offline; the attempt-specific file lets a test exercise the retry.

## Adding a second adapter

1. Create `factory/adapter/<name>.py` with `run(request: Request) -> Reply`.
   - `Request` has `stage`, `prompt` (fully assembled), `workdir`, `tools` (already checked), `allow_write`, `attempt` and `extra_dirs`.
   - Return `Reply(text=<raw reply>, model=<model id>, details={...})`. `details` is merged into the meta file.
   - Map the factory tool names (`Read`, `Grep`, `Glob`, `Edit`, `Write`) to whatever the model offers, and keep shell and web access off.
   - Raise `UsageLimitError` for quota or rate limits, `AdapterTimeout` for timeouts and `AdapterError` for anything else. Never log credentials.
2. Pin any CLI or package it needs in `tools/versions.lock`.
3. Add tests with the CLI or API simulated (see the stub `claude` script in `tests/test_adapter.py`).
4. Select it with `FACTORY_MODEL_ADAPTER=<name>`. Prompts, schemas and stages stay unchanged.

## Smoke test

`.github/workflows/adapter-smoke.yml` runs on `workflow_dispatch` only:

```
gh workflow run adapter-smoke.yml --repo AakashDadhich/security-factory
```

It installs the pinned CLI, checks its flags, runs the `hello` stage (`prompts/hello.md`, `schemas/hello.schema.json`) with the real adapter, validates the reply and uploads `out/hello/` as artifact `hello`. Each run uses a little of the Claude Pro allowance.
