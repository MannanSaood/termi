#!/usr/bin/env python3
"""Verify a signed Termi snapshot in Linux; output a portable, hash-pinned serve map."""
import argparse
import datetime
from email.utils import parsedate_to_datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_file(root, relative):
    if not re.fullmatch(r"[A-Za-z0-9%+._~/-]+", relative) or any(p in ("", ".", "..") for p in relative.split("/")):
        raise ValueError("Unsafe snapshot path")
    current = root
    for part in relative.split("/"):
        current = current / part
        if current.is_symlink() or (hasattr(current, "is_junction") and current.is_junction()):
            raise ValueError("Snapshot aliases are not served")
    if not current.is_file():
        raise ValueError("Missing snapshot file: " + relative)
    return current


def fields(text):
    result, previous = {}, None
    for line in text.splitlines():
        if line.startswith((" ", "\t")) and previous:
            result[previous] += "\n" + line
        else:
            name, value = line.split(":", 1)
            if name in result:
                raise ValueError("Duplicate metadata field")
            result[name], previous = value.strip(), name
    return result


def verify(root, keyring, channel="main"):
    if channel not in ("main", "root", "x11"):
        raise ValueError("Unknown repository channel")
    root = root.resolve()
    signed = safe_file(root, "dists/stable/InRelease")
    release = safe_file(root, "dists/stable/Release")
    public_key = safe_file(root, "repository-keyring.gpg")
    inventory = safe_file(root, "approved-packages.json")
    if inventory.stat().st_size > 32 * 1024**2 or signed.stat().st_size > 1024**2:
        raise ValueError("Oversized metadata")
    if public_key.read_bytes() != keyring.read_bytes():
        raise ValueError("Snapshot does not match the pinned Termi public key")
    payload = subprocess.check_output(["gpgv", "--keyring", str(keyring.resolve()), "--output", "-", str(signed)])
    if payload != release.read_bytes():
        raise ValueError("Release differs from its signed payload")
    signature = safe_file(root, "dists/stable/Release.gpg")
    subprocess.run(["gpgv", "--keyring", str(keyring.resolve()), str(signature), str(release)], check=True)
    header = fields(payload.decode())
    now = datetime.datetime.now(datetime.timezone.utc)
    created = parsedate_to_datetime(header["Date"])
    expires = parsedate_to_datetime(header["Valid-Until"])
    if (created.tzinfo is None or expires.tzinfo is None or expires <= now
            or created > now + datetime.timedelta(minutes=10)
            or not datetime.timedelta(0) < expires - created <= datetime.timedelta(days=46)):
        raise ValueError("Expired or invalid repository metadata")
    if (header.get("Origin") != "Termi" or header.get("Suite") != "stable"
            or header.get("Architectures") != "aarch64" or header.get("Components") != "main"
            or header.get("X-Termi-Inventory-SHA256") != sha(inventory)):
        raise ValueError("Unapproved repository identity or inventory")
    manifest = json.loads(inventory.read_text())
    if manifest.get("schema") != 1 or manifest.get("channel", "main") != channel:
        raise ValueError("Wrong inventory schema/channel")
    records = manifest["packages"]
    if not 1 <= len(records) <= 20000:
        raise ValueError("Invalid package count")
    routes = {}
    prefix = "/apt/" + channel + "/"

    def add(relative, route=None, expected=None, size=None):
        path = safe_file(root, relative)
        checksum = sha(path)
        if (expected and checksum != expected) or (size is not None and path.stat().st_size != size):
            raise ValueError("Snapshot file differs from approved hash/size: " + relative)
        route = prefix + (route or relative)
        if route in routes:
            raise ValueError("Duplicate serving route")
        routes[route] = dict(relative=relative, sha256=checksum, bytes=path.stat().st_size)

    for relative in ["dists/stable/InRelease", "dists/stable/Release", "dists/stable/Release.gpg",
                     "repository-keyring.gpg", "approved-packages.json"]:
        add(relative)
    indexes = {}
    for row in header["SHA256"].splitlines():
        if not row.strip():
            continue
        checksum, size, name = row.split()
        if name not in ("main/binary-aarch64/Packages", "main/binary-aarch64/Packages.gz") or name in indexes:
            raise ValueError("Unexpected signed index path")
        if not re.fullmatch(r"[0-9a-f]{64}", checksum) or not 0 < int(size) <= 64 * 1024**2:
            raise ValueError("Invalid signed index hash/size")
        add("dists/stable/" + name, expected=checksum, size=int(size))
        indexes[name] = checksum
    if "main/binary-aarch64/Packages" not in indexes:
        raise ValueError("Missing signed package index")
    for path in sorted((root / "dists/stable/main/binary-aarch64/by-hash/SHA256").glob("*")):
        if not re.fullmatch(r"[0-9a-f]{64}", path.name):
            raise ValueError("Unsafe immutable index name")
        add(path.relative_to(root).as_posix(), expected=path.name)
    if header.get("Acquire-By-Hash") == "yes":
        for checksum in indexes.values():
            if prefix + "dists/stable/main/binary-aarch64/by-hash/SHA256/" + checksum not in routes:
                raise ValueError("Missing immutable signed index")
    tags = manifest.get("asset_tags", {})
    if tags and set(tags) != {r["file"] for r in records}:
        raise ValueError("Incomplete asset route map")
    approved = {}
    for record in records:
        filename = record["file"]
        if not re.fullmatch(r"[A-Za-z0-9%+._~-]+\.deb", filename):
            raise ValueError("Unsafe package filename")
        tag = tags.get(filename)
        if tag and not re.fullmatch("termi-" + channel + "-[0-9a-f]{24}", tag):
            raise ValueError("Invalid release tag")
        route = "pool/" + (tag + "/" if tag else "") + filename
        add("pool/" + filename, route, record["sha256"])
        identity = (record["name"], record["version"], record["architecture"])
        if identity in approved:
            raise ValueError("Duplicate package identity")
        approved[identity] = (record, route)
    found = set()
    from urllib.parse import unquote
    for paragraph in safe_file(root, "dists/stable/main/binary-aarch64/Packages").read_text().strip().split("\n\n"):
        item = fields(paragraph)
        identity = (item["Package"], item["Version"], item["Architecture"])
        if identity not in approved or identity in found:
            raise ValueError("Index has an unapproved/duplicate package identity")
        record, route = approved[identity]
        # dpkg's flat indexes retain literal percent; release-tag indexes escape
        # portable percent filenames once more. Never decode a flat index twice.
        index_route = unquote(item["Filename"]) if tags else item["Filename"]
        if (item["SHA256"] != record["sha256"] or index_route != route
                or int(item["Size"]) != routes[prefix + route]["bytes"]):
            raise ValueError("Signed index and actual package differ")
        found.add(identity)
    if found != set(approved):
        raise ValueError("Incomplete package index")
    for name, checksum in manifest.get("evidence", {}).items():
        if name == "repository-keyring.gpg":
            if checksum != sha(public_key):
                raise ValueError("Changed public key evidence")
            continue
        if name.startswith(("pool/", "dists/")) or name in ("approved-packages.json", "renewal.json"):
            raise ValueError("Reserved evidence path")
        add(name, expected=checksum)
    return dict(schema=1, channel=channel, profile=manifest.get("publication_profile", "proof"),
                packages=len(records), complete_catalog=False, valid_until=expires.isoformat(), routes=routes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--keyring", type=Path, required=True)
    parser.add_argument("--channel", choices=["main", "root", "x11"], default="main")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.root, args.keyring, args.channel)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(dict(packages=result["packages"], verification_sha256=sha(args.output), valid_until=result["valid_until"])))


if __name__ == "__main__":
    main()
