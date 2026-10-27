import re
import subprocess
import sys

from factory import __version__


def test_main_prints_version():
    result = subprocess.run(
        [sys.executable, "-m", "factory"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert re.fullmatch(r"security-factory \d+\.\d+\.\d+\n", result.stdout)
    assert __version__ in result.stdout
