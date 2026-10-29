import os
import runpy
import sys

import pytm
from pytm import TM

EXIT_NO_MODEL = 3


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: pytm_harness.py <tm.py> [pytm args...]", file=sys.stderr)
        return 2
    model_path, args = sys.argv[1], sys.argv[2:]
    sys.argv = [model_path]
    namespace = runpy.run_path(model_path, run_name="factory_threat_model")
    models = [value for value in namespace.values() if isinstance(value, TM)]
    if len(models) != 1:
        print(f"expected exactly one TM instance bound to a name in {model_path}, found {len(models)}", file=sys.stderr)
        return EXIT_NO_MODEL
    tm = models[0]
    tm.threatsFile = os.path.join(os.path.dirname(pytm.__file__), "threatlib", "threats.json")
    sys.argv = [model_path, *args]
    tm.process()
    return 0


if __name__ == "__main__":
    sys.exit(main())
