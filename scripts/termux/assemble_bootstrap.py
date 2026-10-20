#!/usr/bin/env python3
"""Assemble a debug-only offline APT bootstrap from verified local build outputs.

Uses host APT for runtime closure and dpkg-deb for Debian extraction. The output
is pinned in an APK, not a general-purpose package format or release signer.
Private fixture signing keys never leave the disposable builder container.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

PREFIX = "/data/data/com.terminal.nextgen/files/usr"
ROOTS = ["apt", "bash", "termux-exec", "termux-tools"]


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def signing_key(work):
    home = work / "gnupg"
    home.mkdir(mode=0o700)
    env = {**os.environ, "GNUPGHOME": str(home)}
    gpg = ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", ""]
    run(gpg + ["--quick-generate-key", "Termi APK offline development proof (not release authority)", "ed25519", "sign", "30d"], env=env)
    return gpg, env


def repository(path, packages, gpg, env, expired=False):
    pool = path / "pool"
    pool.mkdir(parents=True)
    for deb in packages:
        shutil.copyfile(deb, pool / deb.name)
    index = path / "dists/proof/main/binary-aarch64/Packages"
    index.parent.mkdir(parents=True)
    index.write_bytes(subprocess.check_output(["dpkg-scanpackages", "--multiversion", "pool", "/dev/null"], cwd=path))
    now = datetime.datetime.now(datetime.timezone.utc)
    date = now - datetime.timedelta(days=2 if expired else 0)
    until = now + datetime.timedelta(days=-1 if expired else 7)
    fmt = "%a, %d %b %Y %H:%M:%S +0000"
    release = index.parents[2] / "Release"
    release.write_text("Origin: TermiProof\nLabel: APK offline proof only\nSuite: proof\nCodename: proof\n"
                       f"Date: {date.strftime(fmt)}\nValid-Until: {until.strftime(fmt)}\n"
                       "Architectures: aarch64\nComponents: main\nSHA256:\n"
                       f" {digest(index)} {index.stat().st_size} main/binary-aarch64/Packages\n")
    run(gpg + ["--armor", "--output", str(release.with_name("InRelease")), "--clearsign", str(release)], env=env)


def select_runtime(work, repo, key):
    apt = work / "apt"
    for name in ["etc/apt.conf.d", "etc/preferences.d", "state/lists/partial", "cache/archives/partial", "log"]:
        (apt / name).mkdir(parents=True)
    (apt / "state/status").write_text("")
    (apt / "etc/apt.conf").write_text("")
    (apt / "etc/sources.list").write_text(f"deb [arch=aarch64 signed-by={key}] file:{repo} proof main\n")
    config = apt / "isolated.conf"
    config.write_text(f'Dir::Etc "{apt / "etc"}";\n#clear APT::Architectures;\n'
                      'APT::Architecture "aarch64";\nAPT::Architectures { "aarch64"; };\n')
    env = {**os.environ, "APT_CONFIG": str(config), "LC_ALL": "C"}
    base = ["apt-get", "-o", f"Dir::State={apt / 'state'}", "-o", f"Dir::State::status={apt / 'state/status'}",
            "-o", f"Dir::Cache={apt / 'cache'}", "-o", f"Dir::Log={apt / 'log'}", "-o", "APT::Sandbox::User=builder",
            "-o", "Acquire::Languages=none", "-o", "APT::Update::Error-Mode=any",
            "-o", "Acquire::AllowInsecureRepositories=false", "-o", "APT::Get::AllowUnauthenticated=false"]
    run(base + ["update"], env=env)
    simulation = subprocess.check_output(base + ["--simulate", "--no-install-recommends", "install", *ROOTS], env=env, text=True)
    (work / "runtime-resolution.txt").write_text(simulation)
    names = re.findall(r"^Inst ([a-z0-9+.-]+)(?::aarch64)? ", simulation, re.M)
    if not set(ROOTS) <= set(names) or not 4 <= len(names) <= 80:
        raise ValueError("Incomplete or unexpectedly broad runtime dependency closure")
    if set(names) & {"python", "libx11", "doxygen", "tor", "pyunbound", "hash-slinger", "git", "nano"}:
        raise ValueError("Unapproved optional tool in runtime closure")
    return names


def unpack(deb, root, prefix, work):
    # These are local, hash-inventoried builder outputs, not network input.
    # Audit every Debian member before letting dpkg-deb write to the rootfs.
    import tarfile
    import io
    data = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(deb)])
    allowed = PREFIX.lstrip("/")
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        names_seen = set()
        non_directories = set()
        total = 0
        for member in tar:
            name = member.name.removeprefix("./").rstrip("/")
            if name in ("", "."):
                continue
            if (name.startswith("/") or any(p in ("", ".", "..") for p in name.split("/"))
                    or any(c in name for c in "\\:\t\n\r") or len(name) > 1024):
                raise ValueError("Unsafe built Debian path")
            if name in names_seen:
                raise ValueError(f"Duplicate built Debian path in {deb.name}: {name}")
            names_seen.add(name)
            total += member.size
            if len(names_seen) > 10000 or member.size > 64 * 1024 * 1024 or total > 256 * 1024 * 1024:
                raise ValueError("Built Debian archive exceeds bootstrap bounds")
            if not (name == allowed or name.startswith(allowed + "/") or member.isdir() and allowed.startswith(name + "/")):
                raise ValueError(f"Package writes outside private prefix: {name}")
            if not (member.isfile() or member.isdir() or member.issym()):
                raise ValueError("Unsupported built Debian member")
            if not member.isdir():
                non_directories.add(name)
            target = root / name
            if target.is_symlink() or target.exists() and not (member.isdir() and target.is_dir()):
                raise ValueError(f"Overlapping built Debian file: {name}")
            for parent in PurePosixPath(name).parents:
                if str(parent) in non_directories or (root / str(parent)).is_symlink():
                    raise ValueError("Built Debian member has alias ancestor")
            if member.issym():
                link = member.linkname
                if link.startswith(PREFIX + "/"):
                    link = os.path.relpath(prefix / link[len(PREFIX) + 1:], target.parent)
                if not link or link.startswith("/") or any(c in link for c in "\\:\t\n\r"):
                    raise ValueError("External built Debian alias")
                # No archive writes below links; final composed alias validation
                # runs across all selected packages before emitting the manifest.
        for name in names_seen:
            if any(str(p) in non_directories for p in PurePosixPath(name).parents):
                raise ValueError("Built Debian member has a non-directory ancestor")
    control = work / (deb.name + ".control")
    run(["dpkg-deb", "--control", str(deb), str(control)])
    text = (control / "control").read_text()
    name = re.search(r"^Package: ([a-z0-9+.-]+)$", text, re.M).group(1)
    run(["dpkg-deb", "--extract", str(deb), str(root)])
    info = prefix / "var/lib/dpkg/info"
    info.mkdir(parents=True, exist_ok=True)
    names = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(deb)])
    with tarfile.open(fileobj=io.BytesIO(names)) as tar:
        listing = ["/" + m.name.removeprefix("./").rstrip("/") for m in tar if m.name not in (".", "./")]
    (info / (name + ".list")).write_text("\n".join(listing) + "\n")
    for f in control.iterdir():
        if f.name == "control":
            continue
        if f.name not in {"preinst", "postinst", "prerm", "postrm", "conffiles", "md5sums", "triggers"} or not f.is_file() or f.is_symlink():
            raise ValueError("Unexpected Debian control member")
        shutil.copyfile(f, info / (name + "." + f.name))
        (info / (name + "." + f.name)).chmod(0o700 if f.name in {"preinst", "postinst", "prerm", "postrm"} else 0o600)
    if not (control / "md5sums").exists():
        # dpkg normally generates this legacy database record while unpacking.
        # Bootstrap extraction must provide it too. Authentication still uses
        # the signed SHA256 repository and APK-pinned SHA256 archive manifest.
        checksums = []
        with tarfile.open(fileobj=io.BytesIO(names)) as tar:
            for member in tar:
                if member.isfile():
                    content = tar.extractfile(member)
                    if content is None:
                        raise ValueError("Missing regular Debian member")
                    with content:
                        value = hashlib.md5(content.read(), usedforsecurity=False).hexdigest()
                    checksums.append(value + "  " + member.name.removeprefix("./"))
        checksum_file = info / (name + ".md5sums")
        checksum_file.write_text("\n".join(checksums) + ("\n" if checksums else ""))
        checksum_file.chmod(0o600)
    with (prefix / "var/lib/dpkg/status").open("a") as out:
        out.write(text.strip() + "\nStatus: install ok unpacked\n\n")


def bundle(prefix, output):
    entries = []
    files = []
    for parent, directories, filenames in os.walk(prefix, followlinks=False):
        for name in sorted(directories + filenames):
            path = Path(parent) / name
            relative = path.relative_to(prefix).as_posix()
            if any(c in relative for c in "\t\n\r\\:"):
                raise ValueError("Invalid bootstrap filename")
            if path.is_symlink():
                target = os.readlink(path)
                if target.startswith(PREFIX + "/"):
                    target = os.path.relpath(prefix / target[len(PREFIX) + 1:], path.parent)
                if target.startswith("/"):
                    raise ValueError(f"External bootstrap link: {relative} -> {target}")
                entries.append(("l", relative, 0, "-", target))
            elif path.is_dir():
                entries.append(("d", relative, 0, "-", "-"))
            elif path.is_file():
                entries.append(("x" if path.stat().st_mode & 0o111 else "f", relative, path.stat().st_size, digest(path), "-"))
                files.append((relative, path))
            else:
                raise ValueError("Special bootstrap file")
    if len(entries) > 10000 or sum(e[2] for e in entries) > 256 * 1024 * 1024:
        raise ValueError("Bootstrap exceeds app extraction bounds")
    aliases = {e[1]: e[4] for e in entries if e[0] == "l"}
    for name, target in aliases.items():
        pending = list(PurePosixPath(name).parent.parts) + target.split("/")
        resolved = []
        hops = 0
        while pending:
            part = pending.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                if not resolved:
                    raise ValueError("Bootstrap alias escapes prefix")
                resolved.pop()
                continue
            resolved.append(part)
            alias = aliases.get("/".join(resolved))
            if alias is not None:
                hops += 1
                if hops > 40:
                    raise ValueError("Bootstrap alias cycle")
                resolved.pop()
                pending = alias.split("/") + pending
    manifest = output / "bootstrap.manifest"
    manifest.write_text("TERMI-BOOTSTRAP-1\n" + "".join("\t".join(map(str, e)) + "\n" for e in sorted(entries, key=lambda e: e[1])))
    archive = output / "bootstrap.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zip:
        for relative, path in sorted(files):
            item = zipfile.ZipInfo(relative, (2026, 1, 1, 0, 0, 0))
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = 0o100600 << 16
            zip.writestr(item, path.read_bytes())
    (output / "bootstrap.properties").write_text("format=1\narchitecture=aarch64\n" + f"prefix={PREFIX}\ngeneration=1\narchive={digest(archive)}\nmanifest={digest(manifest)}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--debs", type=Path, required=True)
    parser.add_argument("--hello", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="termi-assembly-") as temporary:
        work = Path(temporary)
        gpg, env = signing_key(work)
        try:
            key = work / "keyring.gpg"
            key.write_bytes(subprocess.check_output(gpg + ["--export"], env=env))
            debs = sorted(args.debs.glob("*.deb"))
            repository(work / "all", debs, gpg, env)
            names = select_runtime(work, work / "all", key)
            controls = {}
            for deb in debs:
                name = subprocess.check_output(["dpkg-deb", "-f", str(deb), "Package"], text=True).strip()
                if name in controls:
                    raise ValueError("Ambiguous package versions in build outputs")
                controls[name] = deb
            root = work / "rootfs"
            prefix = root / PREFIX.lstrip("/")
            prefix.mkdir(parents=True)
            records = []
            for name in names:
                deb = controls[name]
                unpack(deb, root, prefix, work)
                records.append({"name": name, "file": deb.name, "sha256": digest(deb),
                                "control": subprocess.check_output(["dpkg-deb", "-f", str(deb)], text=True)})
            for name in ["tmp", "etc/apt/apt.conf.d", "etc/apt/preferences.d", "etc/apt/sources.list.d", "var/lib/apt/lists/partial", "var/cache/apt/archives/partial", "var/lib/dpkg/updates", "var/lib/dpkg/triggers", "var/log/apt"]:
                (prefix / name).mkdir(parents=True, exist_ok=True)
            (prefix / "var/lib/dpkg/available").touch()
            scoped_key = prefix / "share/keyrings/termi-proof.gpg"
            scoped_key.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(key, scoped_key)
            hello = args.hello.resolve()
            if digest(hello) != "49f919878ad689a3f804250c28c54fd9bf95fad69a642aa6caee7f2f965cb189":
                raise ValueError("Proof hello differs from verified build")
            repo = prefix / "share/termi/repository"
            repository(repo, [hello, controls["libiconv"]], gpg, env)
            # Two real Debian revisions of the same verified ELF exercise dpkg
            # upgrade/downgrade behavior without expanding the tool catalog.
            revision = work / "hello-revision"
            run(["dpkg-deb", "--raw-extract", str(hello), str(revision)])
            control = revision / "DEBIAN/control"
            text = control.read_text()
            if text.count("Version: 2.12.3-1\n") != 1:
                raise ValueError("Unexpected proof package version")
            control.write_text(text.replace("Version: 2.12.3-1\n", "Version: 2.12.3-2\n"))
            upgraded = work / "hello_2.12.3-2_aarch64.deb"
            run(["dpkg-deb", "--build", "--root-owner-group", str(revision), str(upgraded)])
            repository(prefix / "share/termi/repository-v2", [upgraded, controls["libiconv"]], gpg, env)
            repository(prefix / "share/termi/repository-expired", [hello], gpg, env, expired=True)
            control.write_text(text.replace("Architecture: aarch64\n", "Architecture: amd64\n"))
            foreign = work / "hello_2.12.3-1_amd64.deb"
            run(["dpkg-deb", "--build", "--root-owner-group", str(revision), str(foreign)])
            repository(prefix / "share/termi/repository-wrong-abi", [foreign], gpg, env)
            (prefix / "etc/apt/sources.list").write_text(f"deb [arch=aarch64 signed-by={PREFIX}/share/keyrings/termi-proof.gpg] file:{PREFIX}/share/termi/repository proof main\n")
            (prefix / "etc/apt/apt.conf.d/99termi").write_text(f'Dir::Cache "{PREFIX}/var/cache/apt";\n' +
                'Acquire::AllowInsecureRepositories "false";\nAPT::Get::AllowUnauthenticated "false";\nAcquire::Check-Valid-Until "true";\nAPT::Update::Error-Mode "any";\nAPT::Install-Recommends "false";\nAPT::Install-Suggests "false";\n')
            # The Termux default shared global keyring must be empty.
            trusted = prefix / "etc/apt/trusted.gpg.d"
            if trusted.exists() and list(trusted.iterdir()):
                raise ValueError("Unexpected global APT trust")
            bundle(prefix, args.output)
            (args.output / "runtime-closure.json").write_text(json.dumps({"status": "debug-offline-proof-not-release", "packages": records,
                "proof_packages": [{"file": p.name, "sha256": digest(p),
                                    "control": subprocess.check_output(["dpkg-deb", "-f", str(p)], text=True)}
                                   for p in (hello, upgraded, foreign)],
                "key_sha256": digest(key),
                "key_fingerprint": next(line.split(":")[9] for line in subprocess.check_output(
                    gpg + ["--with-colons", "--fingerprint"], env=env, text=True).splitlines() if line.startswith("fpr:")),
                "resolver": subprocess.check_output(["apt-get", "--version"], text=True).splitlines()[0]}, indent=2) + "\n")
            shutil.copyfile(work / "runtime-resolution.txt", args.output / "runtime-resolution.txt")
        finally:
            run(["gpgconf", "--kill", "gpg-agent"], env=env)
    print("Debug APK bootstrap assembled; device verification required")


if __name__ == "__main__":
    main()
