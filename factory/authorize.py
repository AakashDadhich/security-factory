import argparse
import sys

GUARDED_MODES = ("spec", "change")


def allowed_actors(value: str | None) -> set[str]:
    return {a.strip().casefold() for a in (value or "").split(",") if a.strip()}


def _listed(login: str | None, allowed: set[str]) -> bool:
    return bool(login and login.strip()) and login.strip().casefold() in allowed


def refusal(mode: str, actor: str | None, author: str | None, allowed: str | None) -> str | None:
    if mode not in GUARDED_MODES:
        return None
    listed = allowed_actors(allowed)
    if not listed:
        return "FACTORY_ALLOWED_ACTORS is empty, so nobody can start spec or change runs"
    if not _listed(actor, listed):
        return f"{actor or '<no actor>'} is not in FACTORY_ALLOWED_ACTORS; {mode} run refused"
    # The issue body is fetched after the label is added, so an outside author could edit it in between.
    if not _listed(author, listed):
        return f"issue author {author or '<none>'} is not in FACTORY_ALLOWED_ACTORS; {mode} run refused"
    return None


def authorized(mode: str, actor: str | None, allowed: str | None, author: str | None = None) -> bool:
    return refusal(mode, actor, author, allowed) is None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.authorize", description="Allow spec and change runs only for listed actors")
    parser.add_argument("--mode", required=True)
    parser.add_argument("--actor", default="", help="login of the user who triggered the run")
    parser.add_argument("--author", default="", help="login of the issue author")
    parser.add_argument("--allowed", default="", help="comma-separated GitHub logins (repo variable FACTORY_ALLOWED_ACTORS)")
    args = parser.parse_args(argv)
    reason = refusal(args.mode, args.actor, args.author, args.allowed)
    if reason:
        print(f"error: {reason}", file=sys.stderr)
        return 1
    print(f"authorized: mode {args.mode}" + (f", actor {args.actor}, author {args.author}" if args.mode in GUARDED_MODES else " needs no allowlist"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
