"""Builds the Lambda layer with the packages of requirements.txt.

Terraform runs it as an external data source while it plans (lambda.tf), so
that archive_file can zip the result; CI carries what a plan makes to the
apply job. It reads a JSON query on stdin and prints {"dir": ...}:

- requirements: the pinned packages;
- target: the directory of the layer; the packages go to <target>/python,
  where Lambda looks for them;
- python: the Python version of the function, e.g. "3.14".

The wheels are those of the function's platform (Linux arm64, glibc of
Amazon Linux 2023), whatever runs Terraform. Every file gets the same time,
so the same packages make the same zip and Terraform sees no change. A target
built from the same requirements is used as it is.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PLATFORMS = ("manylinux_2_34_aarch64", "manylinux_2_28_aarch64", "manylinux2014_aarch64")
FIXED_TIME = 315532800  # 1980-01-01, the earliest a zip can hold


def pip_command(scratch):
    """pip of this Python, or of a fresh venv when this one has none."""
    if subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True).returncode == 0:
        return [sys.executable, "-m", "pip"]
    venv = Path(scratch) / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, capture_output=True)
    return [str(venv / "bin" / "python"), "-m", "pip"]


def main():
    query = json.load(sys.stdin)
    requirements = Path(query["requirements"])
    target = Path(query["target"])
    python = query["python"]
    stamp = hashlib.sha256((requirements.read_text() + python + ",".join(PLATFORMS)).encode()).hexdigest()
    stamp_file = target.parent / (target.name + ".stamp")
    if not (stamp_file.exists() and stamp_file.read_text() == stamp and (target / "python").is_dir()):
        shutil.rmtree(target, ignore_errors=True)
        with tempfile.TemporaryDirectory() as scratch:
            command = pip_command(scratch) + [
                "install", "--quiet", "--disable-pip-version-check", "--no-deps", "--no-compile",
                "--only-binary=:all:", "--implementation", "cp", "--python-version", python,
                "--target", str(target / "python"), "-r", str(requirements),
            ]
            for platform in PLATFORMS:
                command += ["--platform", platform]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode:
                sys.stderr.write(result.stdout + result.stderr)
                sys.exit(1)
        # Scripts and caches have no use in a layer and differ between runs.
        shutil.rmtree(target / "python" / "bin", ignore_errors=True)
        for cache in (target / "python").rglob("__pycache__"):
            shutil.rmtree(cache, ignore_errors=True)
        stamp_file.write_text(stamp)
    for path in [target / "python", *(target / "python").rglob("*")]:
        os.utime(path, (FIXED_TIME, FIXED_TIME), follow_symlinks=False)
    json.dump({"dir": str(target)}, sys.stdout)


if __name__ == "__main__":
    main()
