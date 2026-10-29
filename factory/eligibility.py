import argparse
import sys
from dataclasses import dataclass

WIP_PUSH = "work-in-progress-push"
FORK_PR = "fork-pr"
NO_SECRET = "no-secret"
REASONS = (WIP_PUSH, FORK_PR, NO_SECRET)
CHECK_MODE = "check"


@dataclass(frozen=True)
class Decision:
    run_ai: bool
    reason: str


def decide(*, mode: str, event: str, head_is_fork: bool, on_default_branch: bool, has_secret: bool) -> Decision:
    if mode != CHECK_MODE:
        return Decision(True, "")
    if event == "pull_request":
        if head_is_fork:
            return Decision(False, FORK_PR)
    elif event in ("push", "workflow_dispatch"):
        if not on_default_branch:
            return Decision(False, WIP_PUSH)
    else:
        return Decision(False, WIP_PUSH)
    if not has_secret:
        return Decision(False, NO_SECRET)
    return Decision(True, "")


def _flag(value: str) -> bool:
    return value.strip().lower() == "true"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.eligibility",
                                     description="Decide whether the AI stages run in check mode")
    parser.add_argument("--mode", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--head-fork", default="", help="github.event.pull_request.head.repo.fork")
    parser.add_argument("--ref", default="")
    parser.add_argument("--default-branch", default="")
    parser.add_argument("--has-secret", required=True)
    parser.add_argument("--github-output")
    args = parser.parse_args(argv)
    decision = decide(
        mode=args.mode, event=args.event, head_is_fork=_flag(args.head_fork),
        on_default_branch=bool(args.default_branch) and args.ref == f"refs/heads/{args.default_branch}",
        has_secret=_flag(args.has_secret),
    )
    lines = [f"run_ai={'true' if decision.run_ai else 'false'}", f"reason={decision.reason}"]
    print("\n".join(lines))
    if decision.reason:
        print(f"AI stages skipped: {decision.reason}")
    if args.github_output:
        with open(args.github_output, "a") as f:
            f.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
