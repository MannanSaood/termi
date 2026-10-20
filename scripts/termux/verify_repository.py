#!/usr/bin/env python3
"""Run the host repository fixtures with no external container network."""
import argparse
import json
import shutil
import subprocess
from pathlib import Path

from prepare import ROOT, read_lock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    args = parser.parse_args()
    build = args.build.resolve()
    lock = read_lock(build / "context/upstream.lock.json")
    output = build / "repository-fixtures"
    output.mkdir()  # Fail rather than mix evidence from previous runs.
    inputs = output / "input"
    inputs.mkdir()
    for name in ("inventory.json", "hello_2.12.3-1_aarch64.deb", "libiconv_1.19_aarch64.deb"):
        shutil.copyfile(build / "artifacts" / name, inputs / name)
    container = subprocess.check_output([
        "docker", "create", "--network", "none", "--memory", "1g", "--pids-limit", "256",
        "--security-opt", "no-new-privileges", "--entrypoint", "python3", lock["builder_image"],
        "/home/builder/repository_fixture.py"], text=True).strip()
    (output / "container-id.txt").write_text(container + "\n")
    result = None
    with (output / "runner.txt").open("wb") as log:
        try:
            for source, target in ((ROOT / "scripts/termux/repository_fixture.py", "/home/builder/repository_fixture.py"),
                                   (inputs, "/home/builder/fixture-input")):
                subprocess.run(["docker", "cp", str(source), container + ":" + target], check=True,
                               stdout=log, stderr=subprocess.STDOUT)
            result = subprocess.run(["docker", "start", "--attach", container], timeout=120,
                                    stdout=log, stderr=subprocess.STDOUT).returncode
        finally:
            subprocess.run(["docker", "stop", "--timeout", "10", container], check=True,
                           stdout=log, stderr=subprocess.STDOUT)
            state = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[0]["State"]
            (output / "container-state.json").write_text(json.dumps(state, indent=2) + "\n")
            paths = {"results.json": "results.json", "fixture-keyring.gpg": "fixture-keyring.gpg"}
            for case in ("valid", "tampered-signature", "tampered-index", "tampered-deb", "missing-trust-root",
                         "expired-metadata", "no-implicit-downgrade", "incompatible-abi"):
                paths[f"{case}/apt.log"] = case + ".txt"
            copied = True
            for source, target in paths.items():
                copy = subprocess.run(["docker", "cp", container + ":/home/builder/repository-proof/" + source,
                                       str(output / target)], stdout=log, stderr=subprocess.STDOUT)
                copied = copied and copy.returncode == 0
            # Always discard this owned container, including private fixture keys
            # on a failed run. Export only explicitly selected public evidence.
            subprocess.run(["docker", "rm", container], check=True, stdout=log, stderr=subprocess.STDOUT)
    if result != 0 or state["ExitCode"] != 0 or not copied:
        raise SystemExit(f"Host repository fixtures failed; see {output}")
    report = json.loads((output / "results.json").read_text())
    if len(report["results"]) != 8:
        raise SystemExit("Incomplete fixture report")
    print(f"8 host repository fixtures PASS: {output}; not Android package lifecycle proof")


if __name__ == "__main__":
    main()
