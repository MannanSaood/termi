#!/usr/bin/env python3
"""Export built Debian candidates with portable filenames and exact inventories."""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path


def collect(source, destination):
    files = sorted(source.glob("*.deb"))
    if not files:
        raise ValueError("No built packages; refusing success")
    names = set()
    planned = []
    for file in files:
        name = file.name.replace(":", "%3A")
        if (not file.is_file() or file.is_symlink() or name.casefold() in names
                or re.search(r'[<>:"/\\|?*\x00-\x1f]', name)
                or (destination / name).exists()):
            raise ValueError("Unsafe or colliding exported artifact filename")
        names.add(name.casefold())
        fields = subprocess.check_output([
            "dpkg-deb", "-f", str(file), "Package", "Version", "Architecture", "Depends"], text=True)
        if not re.search(r"^Architecture: (aarch64|all)$", fields, re.MULTILINE):
            raise ValueError("Unexpected built package architecture")
        planned.append((file, name, fields))
    destination.mkdir(parents=True, exist_ok=True)
    packages = []
    for file, name, fields in planned:
        target = destination / name
        shutil.copyfile(file, target)
        packages.append({"file": name, "original_file": file.name,
                         "sha256": hashlib.sha256(target.read_bytes()).hexdigest(), "control": fields})
    (destination / "inventory.json").write_text(json.dumps({
        "status": "candidate-not-signed-not-device-verified", "packages": packages,
    }, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    collect(args.source, args.destination)
