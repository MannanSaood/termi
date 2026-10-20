import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from assemble_bootstrap import PREFIX, bundle, unpack


class BootstrapAssemblyContracts(unittest.TestCase):
    def test_rejects_hostile_built_members_before_dpkg_writes(self):
        base = PREFIX.lstrip("/")
        cases = [
            [("../escape", tarfile.REGTYPE, "")],
            [("etc/passwd", tarfile.REGTYPE, "")],
            [(base + "/a", tarfile.LNKTYPE, base + "/b")],
            [(base + "/a", tarfile.FIFOTYPE, "")],
            [(base + "/a", tarfile.SYMTYPE, "/tmp/outside")],
            [(base + "/a", tarfile.REGTYPE, ""), (base + "/a", tarfile.REGTYPE, "")],
            [(base + "/a/b", tarfile.REGTYPE, ""), (base + "/a", tarfile.SYMTYPE, "c")],
        ]
        for entries in cases:
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w") as tar:
                for name, kind, link in entries:
                    member = tarfile.TarInfo(name)
                    member.type, member.linkname = kind, link
                    tar.addfile(member)
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                with patch("assemble_bootstrap.subprocess.check_output", return_value=data.getvalue()), patch("assemble_bootstrap.run") as writer:
                    with self.assertRaises(ValueError):
                        unpack(Path("fixture.deb"), root, root / base, root)
                    writer.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "POSIX alias semantics")
    def test_combined_alias_graph_rejects_escape_and_cycle(self):
        for links in [{"a": ".", "b": "a/../outside"}, {"a": "b", "b": "a"}]:
            with self.subTest(links=links), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                prefix = root / "prefix"
                prefix.mkdir()
                output = root / "output"
                output.mkdir()
                for name, target in links.items():
                    (prefix / name).symlink_to(target)
                with self.assertRaises(ValueError):
                    bundle(prefix, output)
                self.assertFalse((output / "bootstrap.zip").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX alias semantics")
    def test_prefix_alias_is_normalized_and_regular_files_are_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            prefix = root / "prefix"
            (prefix / "bin").mkdir(parents=True)
            (prefix / "bin/tool").write_bytes(b"proof")
            (prefix / "bin/tool").chmod(0o700)
            (prefix / "bin/link").symlink_to(PREFIX + "/bin/tool")
            output = root / "output"
            output.mkdir()
            bundle(prefix, output)
            manifest = (output / "bootstrap.manifest").read_text()
            self.assertIn("l\tbin/link\t0\t-\ttool\n", manifest)
            self.assertIn("x\tbin/tool\t5\t", manifest)


if __name__ == "__main__":
    unittest.main()
