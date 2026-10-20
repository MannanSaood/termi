#!/usr/bin/env python3
"""Build a candidate with the pinned upstream backend; never installs or publishes."""
import argparse
import json
import subprocess
import sys
import uuid
from pathlib import Path

from prepare import ROOT, prepare, read_lock


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=["proof", "bootstrap", "catalog"], default="proof")
    args = parser.parse_args()
    # Report unavailable engine before creating build state or downloading images.
    run(["docker", "info", "--format", "{{.OSType}}"])
    lock = read_lock(ROOT / "packages/termux/upstream.lock.json")
    output = args.output.resolve()
    if output.exists():
        raise SystemExit("Output already exists; use a new build directory")
    prepare(args.upstream.resolve(), output / "context", lock)
    artifacts = output / "artifacts"
    artifacts.mkdir()
    tag = "termi-termux-candidate:" + uuid.uuid4().hex
    run(["docker", "build", "--tag", tag, str(output / "context")])
    container = subprocess.check_output([
        "docker", "create", "--cpus", "2", "--memory", "4g", "--pids-limit", "2048",
        "--security-opt", "no-new-privileges", tag, args.mode], text=True).strip()
    (output / "container-id.txt").write_text(container + "\n")
    result = None
    try:
        # No host filesystem, Docker socket, secrets or devices are mounted.
        result = subprocess.run(["docker", "start", "--attach", container], timeout=7200).returncode
    finally:
        # Docker CLI interrupt need not terminate the attached process itself.
        run(["docker", "stop", "--time", "10", container])
        state = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[0]["State"]
        (output / "container-state.json").write_text(json.dumps(state, indent=2) + "\n")
        copied = subprocess.run(["docker", "cp", container + ":/home/builder/artifacts/.", str(artifacts)]).returncode
        # Preserve a failed container for diagnosis; remove only after evidence copy.
        if copied == 0 and result == 0 and state["ExitCode"] == 0:
            run(["docker", "rm", container])
    if result != 0 or state["ExitCode"] != 0 or copied != 0:
        raise SystemExit("Candidate build failed; inspect retained log/container-state.json")
    if not (artifacts / "inventory.json").is_file():
        raise SystemExit("Missing package inventory; no successful candidate")
    if args.mode == "proof":
        run([sys.executable, str(ROOT / "scripts/termux/proof_sbom.py"), "--build", str(output)])
    print(f"Candidate artifacts: {artifacts}. Not signed, installed or device verified.")


if __name__ == "__main__":
    main()
