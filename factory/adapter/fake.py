import os
from pathlib import Path

from factory.adapter import AdapterError, Reply, Request


def run(request: Request) -> Reply:
    directory = os.environ.get("FACTORY_FAKE_RESPONSES")
    if not directory:
        raise AdapterError("FACTORY_FAKE_RESPONSES is not set")
    base = Path(directory)
    for candidate in (base / f"{request.stage}.{request.attempt}.json", base / f"{request.stage}.json"):
        if candidate.is_file():
            return Reply(text=candidate.read_text(), model="fake", details={"response_file": str(candidate)})
    raise AdapterError(f"no canned response for stage '{request.stage}' in {base}")
