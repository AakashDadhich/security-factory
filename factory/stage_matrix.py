from dataclasses import dataclass

from factory.eligibility import REASONS as AI_SKIP_REASONS

PLATFORMS = ("web", "macos", "ios")
MODES = ("spec", "check", "fix", "change")
SKIP_REASONS = ("fork-pr", "not-applicable")


@dataclass(frozen=True)
class Stage:
    name: str
    platforms: tuple[str, ...] = PLATFORMS
    modes: tuple[str, ...] = MODES
    skippable: tuple[str, ...] = ()
    ai: bool = False


STAGES = (
    Stage("plan", modes=("spec", "change")),
    Stage("threat-model", modes=("spec", "change", "check"), ai=True),
    Stage("codegen-ai", modes=("spec", "change", "fix")),
    Stage("codegen-commit", modes=("spec", "change", "fix")),
    Stage("review", modes=("spec", "change", "fix", "check"), ai=True),
    Stage("secrets"),
    Stage("sast-semgrep"),
    Stage("sast-codeql", platforms=("web",)),
    Stage("sast-eslint", platforms=("web",)),
    Stage("deps-sbom"),
    Stage("dast-web", platforms=("web",)),
)


def expected(platform: str, mode: str) -> list[Stage]:
    if platform not in PLATFORMS:
        raise ValueError(f"unknown platform {platform!r}")
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}")
    return [s for s in STAGES if platform in s.platforms and mode in s.modes]
