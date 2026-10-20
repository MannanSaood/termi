#!/usr/bin/env python3
"""Validate an approved repository snapshot and renew its signed APT metadata.

Run only in a dedicated signing environment, never the package build container.
The private signing subkey is supplied by the operator/Actions secret store.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Invalid repository root")
    # The signer consumes a reviewed Git snapshot. Reject aliases and special
    # files before invoking any parser or writing metadata beneath that tree.
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("Repository contains an alias or special file")
        if path.is_file():
            total += path.stat().st_size
    if total > 512 * 1024 * 1024:
        raise ValueError("Repository exceeds catalog budget")
    if (root / "approved-packages.json").stat().st_size > 128 * 1024:
        raise ValueError("Oversized approval")
    manifest = json.loads((root / "approved-packages.json").read_text())
    if manifest.get("schema") != 1 or manifest.get("roots") != ["apt", "bash", "termux-exec", "termux-tools", "hello", "git", "gh"]:
        raise ValueError("Unapproved catalog roots")
    records = manifest["packages"]
    if not 7 <= len(records) <= 90:
        raise ValueError("Unexpected runtime closure")
    files, names = set(), set()
    for record in records:
        name, filename = record["name"], record["file"]
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", name) or name in names:
            raise ValueError("Ambiguous package identity")
        if not re.fullmatch(r"[A-Za-z0-9%+._~-]+\.deb", filename) or filename in files:
            raise ValueError("Unsafe or duplicate package filename")
        path = root / "pool" / filename
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 96 * 1024 * 1024:
            raise ValueError("Invalid package file")
        if digest(path) != record["sha256"]:
            raise ValueError("Package differs from approved inventory")
        fields = subprocess.check_output(["dpkg-deb", "-f", str(path), "Package", "Version", "Architecture"], text=True)
        expected = f"Package: {name}\nVersion: {record['version']}\nArchitecture: {record['architecture']}\n"
        if fields != expected or record["architecture"] not in ("aarch64", "all"):
            raise ValueError("Debian metadata differs from approval")
        files.add(filename)
        names.add(name)
    if not set(manifest["roots"]) <= names or {p.name for p in (root / "pool").iterdir()} != files:
        raise ValueError("Incomplete closure or unapproved package in pool")
    evidence = manifest.get("evidence", {})
    if not isinstance(evidence, dict) or len(evidence) > 512:
        raise ValueError("Invalid evidence approval")
    for name, expected in evidence.items():
        if (not re.fullmatch(r"[A-Za-z0-9%+._/-]+", name)
                or any(part in ("", ".", "..") for part in name.split("/"))
                or name.startswith(("pool/", "dists/"))
                or name in ("approved-packages.json", "renewal.json")
                or not re.fullmatch(r"[0-9a-f]{64}", expected)
                or digest(root / name) != expected):
            raise ValueError("Evidence differs from operator approval")
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
              and not p.relative_to(root).as_posix().startswith(("pool/", "dists/"))
              and p.name not in ("approved-packages.json", "renewal.json")}
    if actual != set(evidence):
        raise ValueError("Unapproved repository evidence")
    return manifest


def renew(root, fingerprint, passphrase):
    manifest = validate(root)
    if not re.fullmatch(r"[0-9A-F]{40}", fingerprint):
        raise ValueError("Invalid signing fingerprint")
    index = root / "dists/stable/main/binary-aarch64/Packages"
    index.parent.mkdir(parents=True, exist_ok=True)
    data = subprocess.check_output(["dpkg-scanpackages", "--multiversion", "pool", "/dev/null"], cwd=root)
    index.write_bytes(data)
    by_hash = index.parent / "by-hash/SHA256"
    by_hash.mkdir(parents=True, exist_ok=True)
    (by_hash / digest(index)).write_bytes(data)
    now = datetime.datetime.now(datetime.timezone.utc)
    # Weekly renewal leaves room for transient outages without disabling expiry.
    expiry = now + datetime.timedelta(days=45)
    date_format = "%a, %d %b %Y %H:%M:%S +0000"
    release = index.parents[2] / "Release"
    evidence = ""
    for label, name in [("Inventory", "approved-packages.json"), ("Provenance", "catalog.provenance.json"),
                        ("SBOM", "catalog.sbom.cdx.json"), ("Sources", "sources.json")]:
        if (root / name).is_file():
            evidence += f"X-Termi-{label}-SHA256: {digest(root / name)}\n"
    release.write_text(
        "Origin: Termi\nLabel: Termi approved ARM64 packages\nSuite: stable\nCodename: stable\n"
        f"Date: {now.strftime(date_format)}\nValid-Until: {expiry.strftime(date_format)}\n"
        "Architectures: aarch64\nComponents: main\nAcquire-By-Hash: yes\n" + evidence +
        f"SHA256:\n {digest(index)} {len(data)} main/binary-aarch64/Packages\n",
        encoding="utf-8",
    )
    command = ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase-fd", "0",
               "--local-user", fingerprint + "!"]
    subprocess.run(command + ["--armor", "--output", str(release.with_name("InRelease")), "--clearsign", str(release)],
                   input=passphrase.encode(), check=True)
    subprocess.run(command + ["--armor", "--output", str(release.with_name("Release.gpg")), "--detach-sign", str(release)],
                   input=passphrase.encode(), check=True)
    subprocess.run(["gpgv", "--keyring", str((root / "repository-keyring.gpg").resolve()),
                    str(release.with_name("InRelease"))], check=True)
    (root / "renewal.json").write_text(json.dumps({
        "generated": now.isoformat(), "valid_until": expiry.isoformat(),
        "signing_subkey": fingerprint, "package_count": len(manifest["packages"]),
        "inventory_sha256": digest(root / "approved-packages.json"),
        "verification": "local approved bytes; metadata renewal is not package rebuilding",
    }, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--signing-fingerprint", required=True)
    parser.add_argument("--inventory-sha256", required=True)
    args = parser.parse_args()
    if not re.fullmatch("[0-9a-f]{64}", args.inventory_sha256) or digest(args.root / "approved-packages.json") != args.inventory_sha256:
        raise ValueError("Catalog lacks operator hash approval")
    renew(args.root.resolve(), args.signing_fingerprint, os.environ["TERMI_SIGNING_PASSPHRASE"])


if __name__ == "__main__":
    main()
