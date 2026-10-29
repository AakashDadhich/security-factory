import argparse
import sys

GUARDED_MODES = ("spec", "change")


def allowed_actors(value: str | None) -> set[str]:
    return {a.strip().casefold() for a in (value or "").split(",") if a.strip()}


def authorized(mode: str, actor: str | None, allowed: str | None) -> bool:
    if mode not in GUARDED_MODES:
        return True
    return bool(actor and actor.strip()) and actor.strip().casefold() in allowed_actors(allowed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.authorize", description="Allow spec and change runs only for listed actors")
    parser.add_argument("--mode", required=True)
    parser.add_argument("--actor", default="")
    parser.add_argument("--allowed", default="", help="comma-separated GitHub logins (repo variable FACTORY_ALLOWED_ACTORS)")
    args = parser.parse_args(argv)
    if authorized(args.mode, args.actor, args.allowed):
        print(f"authorized: mode {args.mode}" + (f", actor {args.actor}" if args.mode in GUARDED_MODES else " needs no allowlist"))
        return 0
    if not allowed_actors(args.allowed):
        print("error: FACTORY_ALLOWED_ACTORS is empty, so nobody can start spec or change runs", file=sys.stderr)
    else:
        print(f"error: {args.actor or '<no actor>'} is not in FACTORY_ALLOWED_ACTORS; {args.mode} run refused", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
