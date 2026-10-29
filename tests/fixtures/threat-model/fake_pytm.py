import shutil
import sys
from pathlib import Path

args = [a for a in sys.argv[1:] if a != "-I"]
source = Path(args[0]).read_text()
if "FAKE_PYTM_FAIL" in source:
    print("Traceback: NameError: name 'Sevrer' is not defined", file=sys.stderr)
    sys.exit(1)
if "--dfd" in args:
    print("digraph tm {\n  user -> web;\n}")
if "--json" in args:
    shutil.copyfile(Path(__file__).with_name("pytm.json"), args[args.index("--json") + 1])
