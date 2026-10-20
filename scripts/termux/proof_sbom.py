#!/usr/bin/env python3
"""Describe the bounded hello candidate; not a signed release attestation."""
import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    args = parser.parse_args()
    artifacts = args.build / "artifacts"
    context = args.build / "context"
    inventory = json.loads((artifacts / "inventory.json").read_text())
    lock = json.loads((context / "upstream.lock.json").read_text())
    source = json.loads((context / "source.json").read_text())
    if lock["commit"] != "a31e3cc46b11d3a19d7cb12c6f56acdaa4c8033a":
        raise SystemExit("Review the bounded SBOM recipe definitions for this new upstream commit")
    if sha(context / "source.tar") != source["archive_sha256"]:
        raise SystemExit("Committed source archive changed")
    definitions = {
        "hello": ("2.12.3-1", "application", "GPL-3.0",
                  "https://mirrors.kernel.org/gnu/hello/hello-2.12.3.tar.gz",
                  "0d5f60154382fee10b114a1c34e785d8b1f492073ae2d3a6f7b147687b366aa0"),
        "libiconv": ("1.19", "library", "LGPL-2.1, GPL-3.0",
                     "https://mirrors.kernel.org/gnu/libiconv/libiconv-1.19.tar.gz",
                     "88dd96a8c0464eca144fc791ae60cd31cd8ee78321e67397e25fc095c4a19aa6"),
    }
    components = []
    inputs = []
    for name, (version, kind, license_name, url, source_hash) in definitions.items():
        filename = f"{name}_{version}_aarch64.deb"
        entries = [entry for entry in inventory["packages"] if entry["file"] == filename]
        if len(entries) != 1 or sha(artifacts / filename) != entries[0]["sha256"]:
            raise SystemExit(f"Missing or changed candidate: {filename}")
        if f"Package: {name}\nVersion: {version}\nArchitecture: aarch64\n" not in entries[0]["control"]:
            raise SystemExit("Candidate control identity differs")
        components.append({
            "type": kind, "bom-ref": name, "name": name, "version": version,
            "purl": f"pkg:deb/termi/{name}@{version}?arch=aarch64",
            "hashes": [{"alg": "SHA-256", "content": entries[0]["sha256"]}],
            "licenses": [{"license": {"name": license_name + " (upstream recipe declaration)"}}],
            "externalReferences": [{"type": "distribution", "url": url}],
            "properties": [{"name": "termi:source:sha256", "value": source_hash},
                           {"name": "termi:runtime-platform", "value": "Android bionic, ARM64, minimum API26"}],
        })
        inputs.append({"package": name, "source_url": url, "source_sha256": source_hash})
    provenance = {
        "status": "unsigned-local-candidate-not-release-attestation",
        "scope": "hello and libiconv; excludes platform bionic, bootstrap and optional build subpackages",
        "recipe_commit": lock["commit"], "repository": lock["repository"],
        "builder_image": lock["builder_image"], "source": source,
        "inputs": inputs, "outputs": inventory["packages"],
        "context_sha256": {name: sha(context / name) for name in
                           ("Dockerfile", "build-in-container.sh", "collect_artifacts.py", "patches.json", "upstream.lock.json", "source.json")
                           if (context / name).is_file()},
        "command": "./build-package.sh -a aarch64 -j 2 hello",
        "package_api": 26, "prefix": lock["prefix"],
        "network": "Online source/host-tool retrieval with upstream checksum checks; no APT repository signature verification",
        "reproducibility": "This record identifies one build; independent comparisons require separate evidence",
    }
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "bom-ref": "proof",
                                     "name": "Termi hello candidate", "version": "2.12.3-1"},
                     "properties": [{"name": "termi:scope", "value": provenance["scope"]},
                                    {"name": "termi:status", "value": provenance["status"]}]},
        "components": components,
        "dependencies": [{"ref": "proof", "dependsOn": ["hello"]},
                         {"ref": "hello", "dependsOn": ["libiconv"]},
                         {"ref": "libiconv", "dependsOn": []}],
    }
    for name, data in (("proof.sbom.cdx.json", bom), ("proof.provenance.json", provenance)):
        (artifacts / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    files = sorted([*artifacts.glob("*.deb"), *artifacts.glob("*.json")])
    (artifacts / "SHA256SUMS").write_text(
        "".join(f"{sha(file)}  ./{file.name}\n" for file in files), encoding="utf-8")
    print("Wrote bounded candidate SBOM/provenance; no signature or release certification")


if __name__ == "__main__":
    main()
