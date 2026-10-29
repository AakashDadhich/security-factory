# Runner facts

Verified on 2026-10-27 against the sources listed at the end. Runner images update roughly weekly, so re-check before relying on a version.

## Preinstalled tools

| Tool | `ubuntu-24.04` | `macos-15` (arm64) |
|---|---|---|
| git | yes, 2.55.0 (Git LFS 3.8.0) | yes, 2.55.0 (Git LFS 3.8.0) |
| Python | yes, 3.12.3 | yes, 3.14.7 |
| Node | yes, 22.23.3 | yes, 22.23.2 |
| Docker | yes, client and server 28.0.4, Compose 2.38.2, Buildx 0.38.0 | no |
| jq | yes, 1.7 | yes, 1.8.2 |
| yq | yes, 4.54.1 | yes, 4.53.6 |
| make | yes, GNU make 4.3 (apt package `4.3-4.1build2`) | yes, GNU Make 3.81 at `/usr/bin/make` (not in the readme; seen in selftest run `40746602330` on 2026-10-28) |
| pipx | yes, 1.16.7 | yes, 1.17.2 |
| Xcode | no | yes, 16.4 default (16F6); also 16.0 to 16.3 and 26.0.1 to 26.3; Command Line Tools 16.4 |
| SwiftLint | no | no (not listed) |
| Homebrew | yes, 7.0.9 | yes, 6.0.22 |

Image versions read: `ubuntu-24.04` image `20261023.334.3`, `macos-15-arm64` image `20260907.0337.1`.

What this means for later chunks:
- macOS jobs have no Docker, so container-based tools (for example ZAP and MobSF) run on `ubuntu-24.04`.
- `make` isn't listed in the `macos-15` readme, but `/usr/bin/make` (GNU Make 3.81, from the Command Line Tools) is present. macOS jobs run `python -m factory.platform_check ensure-make` first (it installs GNU make with Homebrew if it's ever missing), then can use `make`.
- SwiftLint isn't on either image, so it must be installed through `tools/versions.lock`.
- pytm (1.4.0) is a library with no console script, so pipx can't install it. It uses lock kind `venv`: `python -m factory.tools install pytm` creates `~/.factory/venvs/pytm` with the job's Python 3.12 and installs `tools/pytm/requirements.txt` with `--require-hashes --no-deps --only-binary :all:` (pytm plus pydantic 2.14.1, pydantic-core 2.50.1, annotated-types, typing-extensions, typing-inspection; hashes are for the linux x86_64 CPython 3.12 wheels). Run models with `~/.factory/venvs/pytm/bin/python`.
- The `ubuntu-latest` label moves to Ubuntu 26.04 in November 2026. The factory pins `ubuntu-24.04`, so it isn't affected.

## Usage limits (GitHub Free, standard GitHub-hosted runners)

| Limit | Value |
|---|---|
| Total concurrent jobs | 20 |
| Concurrent macOS jobs (counted inside the 20) | 5 |
| Job execution time | 6 hours per job; the job is terminated and fails |
| Workflow run time | 35 days per run, including waiting and approval time; the run is cancelled |
| Workflow runs queued | 500 runs per 10 seconds; extra webhook-triggered runs are dropped, and a run with reusable workflows counts as 1 |

Jobs above the concurrency cap wait in the queue until a slot frees up. GitHub Support can raise concurrency limits, but not the time limits.

## Sources
- https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md (commit `aa2d9f91221232debee20fcb34746384a3688579`, 2026-10-25)
- https://github.com/actions/runner-images/blob/main/images/macos/macos-15-arm64-Readme.md (commit `f95c0c791f690fa64eaf9788bea06643a4176db5`, 2026-09-11)
- https://docs.github.com/en/actions/reference/limits (fetched 2026-10-27)
