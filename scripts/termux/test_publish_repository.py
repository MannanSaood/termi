import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import publish_repository as publisher


@unittest.skipUnless(shutil.which("dpkg-deb") and shutil.which("gpg"), "Linux signing tools required")
class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "apt"
        (self.root / "pool").mkdir(parents=True)
        roots = ["apt", "bash", "termux-exec", "termux-tools", "hello", "git", "gh"]
        records = []
        for name in roots:
            package = Path(self.temp.name) / ("fixture-" + name)
            (package / "DEBIAN").mkdir(parents=True)
            (package / "DEBIAN/control").write_text(
                f"Package: {name}\nVersion: 1.0\nArchitecture: aarch64\nMaintainer: Fixture\nDescription: fixture\n")
            target = self.root / "pool" / f"{name}_1.0_aarch64.deb"
            subprocess.run(["dpkg-deb", "--build", str(package), str(target)], check=True, stdout=subprocess.DEVNULL)
            records.append(dict(name=name, file=target.name, version="1.0", architecture="aarch64", sha256=publisher.digest(target)))
        self.approval = dict(schema=1, roots=roots, packages=records)
        self.save()

    def tearDown(self):
        self.temp.cleanup()

    def save(self):
        (self.root / "approved-packages.json").write_text(json.dumps(self.approval))

    def test_approved_inventory_and_hashes(self):
        self.assertEqual(7, len(publisher.validate(self.root)["packages"]))
        path = self.root / "pool" / self.approval["packages"][0]["file"]
        path.write_bytes(path.read_bytes() + b"tamper")
        with self.assertRaises(ValueError):
            publisher.validate(self.root)

    def test_alias_paths_and_unapproved_files(self):
        (self.root / "pool/foreign.deb").write_bytes(b"foreign")
        with self.assertRaises(ValueError):
            publisher.validate(self.root)
        (self.root / "pool/foreign.deb").unlink()
        (self.root / "dists").symlink_to(Path(self.temp.name), target_is_directory=True)
        with self.assertRaises(ValueError):
            publisher.validate(self.root)

    def test_confused_identity_version_and_abi(self):
        for field, value in [("name", "../escape"), ("file", "../escape.deb"),
                             ("version", "2.0"), ("architecture", "arm")]:
            old = self.approval["packages"][0][field]
            self.approval["packages"][0][field] = value
            self.save()
            with self.assertRaises(ValueError):
                publisher.validate(self.root)
            self.approval["packages"][0][field] = old
        self.approval["packages"].append(self.approval["packages"][0])
        self.save()
        with self.assertRaises(ValueError):
            publisher.validate(self.root)

    def test_retains_immutable_old_versions_and_pins_evidence(self):
        package = Path(self.temp.name) / "fixture-git"
        control = package / "DEBIAN/control"
        control.write_text(control.read_text().replace("Version: 1.0", "Version: 1.0-1"))
        target = self.root / "pool/git_1.0-1_aarch64.deb"
        subprocess.run(["dpkg-deb", "--build", str(package), str(target)], check=True, stdout=subprocess.DEVNULL)
        self.approval["packages"].append(dict(name="git", file=target.name, version="1.0-1",
                                               architecture="aarch64", sha256=publisher.digest(target)))
        proof = self.root / "provenance.json"
        proof.write_text('{"reviewed": true}\n')
        self.approval["evidence"] = {"provenance.json": publisher.digest(proof)}
        self.save()
        self.assertEqual(8, len(publisher.validate(self.root)["packages"]))
        proof.write_text('{"reviewed": false}\n')
        with self.assertRaises(ValueError):
            publisher.validate(self.root)

    def test_signed_renewal_and_hostile_signature(self):
        home = Path(self.temp.name) / "gpg"
        home.mkdir(mode=0o700)
        with patch.dict(os.environ, {"GNUPGHOME": str(home)}):
            subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-generate-key",
                            "Test only", "ed25519", "sign", "1d"], check=True, capture_output=True)
            listing = subprocess.check_output(["gpg", "--with-colons", "--list-keys"], text=True)
            fp = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
            (self.root / "repository-keyring.gpg").write_bytes(subprocess.check_output(["gpg", "--export", fp]))
            self.approval["evidence"] = {"repository-keyring.gpg": publisher.digest(self.root / "repository-keyring.gpg")}
            self.save()
            publisher.renew(self.root, fp, "")
            signed = self.root / "dists/stable/InRelease"
            self.assertIn("Valid-Until:", signed.read_text())
            self.assertIn("Acquire-By-Hash: yes", signed.read_text())
            index = self.root / "dists/stable/main/binary-aarch64/Packages"
            self.assertEqual(index.read_bytes(), (index.parent / "by-hash/SHA256" / publisher.digest(index)).read_bytes())
            signed.write_text(signed.read_text().replace("Origin: Termi", "Origin: Evil"))
            self.assertNotEqual(0, subprocess.run(
                ["gpgv", "--keyring", str(self.root / "repository-keyring.gpg"), str(signed)], capture_output=True).returncode)


if __name__ == "__main__":
    unittest.main()
