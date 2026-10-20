import io
import json
import os
import random
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from prepare import ROOT, read_lock, replace_once, validate_source
from collect_artifacts import collect


def archive(entries):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as output:
        for name, kind, content in entries:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            if kind == tarfile.SYMTYPE:
                entry.linkname = content
                output.addfile(entry)
            elif kind == tarfile.REGTYPE:
                encoded = content.encode()
                entry.size = len(encoded)
                output.addfile(entry, io.BytesIO(encoded))
            else:
                output.addfile(entry)
    return data.getvalue()


class PreparationContracts(unittest.TestCase):
    def make_deb(self, root, architecture):
        package = root / "package"
        (package / "DEBIAN").mkdir(parents=True)
        (package / "DEBIAN/control").write_text(
            "Package: epoch-fixture\nVersion: 1:2\n"
            f"Architecture: {architecture}\nMaintainer: Fixture <fixture@example.invalid>\n"
            "Description: Disposable export fixture\n")
        source = root / "source"
        source.mkdir()
        deb = source / f"epoch-fixture_1:2_{architecture}.deb"
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(package), str(deb)],
                       check=True, stdout=subprocess.DEVNULL)
        return source, deb

    @unittest.skipUnless(shutil.which("dpkg-deb"), "Requires host dpkg-deb")
    def test_epoch_export_is_lossless_and_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, deb = self.make_deb(root, "aarch64")
            output = root / "output"
            collect(source, output)
            self.assertEqual(deb.read_bytes(), (output / "epoch-fixture_1%3A2_aarch64.deb").read_bytes())
            record = json.loads((output / "inventory.json").read_text())["packages"][0]
            self.assertEqual(deb.name, record["original_file"])
            self.assertIn("Version: 1:2\n", record["control"])
            with self.assertRaises(ValueError):
                collect(source, output)

    @unittest.skipUnless(shutil.which("dpkg-deb"), "Requires host dpkg-deb")
    def test_foreign_architecture_artifact_is_not_exported(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, _ = self.make_deb(root, "amd64")
            output = root / "output"
            with self.assertRaises(ValueError):
                collect(source, output)
            self.assertFalse(output.exists())

    def test_rejects_unpinned_image_or_wrong_runtime_identity(self):
        original = json.loads((ROOT / "packages/termux/upstream.lock.json").read_text())
        for key, value in [("builder_image", "ghcr.io/termux/package-builder:latest"),
                           ("commit", "master"), ("application_id", "com.termux"),
                           ("prefix", "/sdcard/usr"), ("architecture", "x86_64")]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as folder:
                file = Path(folder) / "lock.json"
                file.write_text(json.dumps({**original, key: value}))
                with self.assertRaises(ValueError):
                    read_lock(file)

    def test_source_archive_rejects_escape_and_special_files(self):
        for name, kind, content in [
            ("../outside", tarfile.REGTYPE, "data"),
            ("/absolute", tarfile.REGTYPE, "data"),
            ("C:/drive", tarfile.REGTYPE, "data"),
            ("link", tarfile.SYMTYPE, "../../outside"),
            ("link", tarfile.SYMTYPE, "/etc/passwd"),
            ("hard", tarfile.LNKTYPE, ""), ("device", tarfile.CHRTYPE, "")]:
            with self.subTest(name=name, kind=kind), self.assertRaises(ValueError):
                validate_source(archive([(name, kind, content)]))

    def test_source_alias_parent_and_case_collision_rejected(self):
        with self.assertRaises(ValueError):
            validate_source(archive([("a", tarfile.SYMTYPE, "b"), ("a/file", tarfile.REGTYPE, "x")]))
        with self.assertRaises(ValueError):
            validate_source(archive([("A", tarfile.REGTYPE, "x"), ("a", tarfile.REGTYPE, "y")]))

    def test_normal_git_tree_preserves_in_tree_unix_aliases(self):
        validate_source(archive([("scripts", tarfile.DIRTYPE, ""),
                                 ("scripts/example", tarfile.REGTYPE, "hello"),
                                 ("scripts/alias", tarfile.SYMTYPE, "example")]))

    def test_alias_chains_cannot_escape_or_cycle(self):
        for entries in (
            [("a", tarfile.SYMTYPE, "."), ("b", tarfile.SYMTYPE, "a/../outside")],
            [("a", tarfile.SYMTYPE, "b"), ("b", tarfile.SYMTYPE, "a")],
        ):
            with self.assertRaises(ValueError):
                validate_source(archive(entries))

    @unittest.skipUnless(os.name == "posix", "POSIX symlink oracle requires a Linux host/container")
    def test_generated_alias_graphs_against_real_filesystem(self):
        rng = random.Random(7007)
        targets = [".", "..", "../outside", "a", "b", "c", "d", "missing",
                   "a/../outside", "b/../../outside", "c/missing", "missing/../a"]
        for trial in range(200):
            entries = [(name, tarfile.SYMTYPE, rng.choice(targets)) for name in "abcd"]
            try:
                validate_source(archive(entries))
            except ValueError:
                continue  # Conservative rejection is permitted for build input.
            with self.subTest(trial=trial), tempfile.TemporaryDirectory() as folder:
                root = Path(folder).resolve()
                for name, _, target in entries:
                    (root / name).symlink_to(target)
                for name, _, _ in entries:
                    # Resolve using real POSIX symlinks, independently of the
                    # parser's alias algorithm. Escapes and cycles must not pass.
                    resolved = (root / name).resolve()
                    self.assertTrue(resolved.is_relative_to(root), entries)

    def test_upstream_patch_drift_fails_without_overwriting(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "build.sh"
            for content in ("upstream removed hook", "boundary\nboundary\n"):
                path.write_text(content)
                with self.assertRaises(ValueError):
                    replace_once(path, "boundary", "replacement")
                self.assertEqual(content, path.read_text())


if __name__ == "__main__":
    unittest.main()
