#!/usr/bin/env python3
"""Record the exact approved Debian closure and its pinned recipe provenance."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import quote


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--recipes", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    args = parser.parse_args()
    approved = json.loads((args.repository / "approved-packages.json").read_text())
    lock = json.loads((args.context / "upstream.lock.json").read_text())
    parents = {}
    for tree in ["packages", "root-packages", "x11-packages"]:
        for recipe in (args.recipes / tree).glob("*/build.sh"):
            parents[recipe.parent.name] = recipe
            for subpackage in recipe.parent.glob("*.subpackage.sh"):
                parents[subpackage.name.removesuffix(".subpackage.sh")] = recipe
    components, relationships = [], []
    names = {record["name"] for record in approved["packages"]}
    for record in approved["packages"]:
        path = args.repository / "pool" / record["file"]
        if sha(path) != record["sha256"]:
            raise ValueError("Approved package changed")
        name = record["name"]
        recipe = parents[name]
        relative = recipe.relative_to(args.recipes).as_posix()
        text = recipe.read_text()
        license_value = re.search(r'^TERMUX_PKG_LICENSE=(.+)$', text, re.M)
        dependencies = subprocess.check_output(["dpkg-deb", "-f", str(path), "Depends"], text=True).strip()
        components.append({
            "type": "application" if name in {"git", "gh", "hello"} else "library",
            "bom-ref": name, "name": name, "version": record["version"],
            "purl": f"pkg:deb/termi/{name}@{quote(record['version'], safe='')}?arch={record['architecture']}",
            "hashes": [{"alg": "SHA-256", "content": record["sha256"]}],
            "licenses": [{"license": {"name": (license_value[1].strip('"') if license_value else "See recipe") + " (recipe declaration)"}}],
            "externalReferences": [{"type": "vcs", "url": f"https://github.com/termux/termux-packages/blob/{lock['commit']}/{relative}"}],
            "properties": [{"name": "termi:recipe:sha256", "value": sha(recipe)},
                           {"name": "termi:debian:depends", "value": dependencies}],
        })
        required = [n for n in re.findall(r"(?:^|[,|])\s*([a-z0-9+.-]+)", dependencies) if n in names]
        relationships.append({"ref": name, "dependsOn": sorted(set(required))})
    provenance = {
        "scope": "Exact approved ARM64 runtime closure; excludes Android bionic and build tools",
        "recipe_commit": lock["commit"], "prefix": lock["prefix"], "package_api": lock["package_api"],
        "builder_image": lock["builder_image"], "roots": approved["roots"],
        "package_records_sha256": hashlib.sha256(json.dumps(approved["packages"], sort_keys=True).encode()).hexdigest(),
        "patch_manifest_sha256": sha(args.context / "patches.json"),
        "reproducibility": "Cache-assisted source builds; full clean closure reproduction not claimed",
        "network": "Source archives and Go modules retrieved online with recipe hashes/Go module verification; metadata renewal is not a source rebuild",
        "go_subprocess": "CGO enabled; Android linker mode uses system sh with positional arguments and installed Termux libc exec adapter",
        "gh_dependency_override": {
            "module": "github.com/gabriel-vasile/mimetype", "version": "v1.4.16",
            "sum": "h1:5izNFuvA37st1dDRAcA7TtmngBmRgiIPDmTtiEvjx1E=",
            "reason": "v1.4.15 retracted for quadratic CDF parsing; upstream fixed release",
        },
        "sources": "Pinned upstream recipes declare exact upstream source URLs/hashes; local recipe overlays and build scripts accompany this catalog",
    }
    (args.repository / "catalog.provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    (args.repository / "catalog.sbom.cdx.json").write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "name": "Termi approved package catalog", "version": "1"}},
        "components": components, "dependencies": relationships,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
