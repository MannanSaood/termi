#!/usr/bin/env python3
"""Offline HOST APT fixture tests in the pinned builder; never install packages.

Uses a disposable signing key inside the container. It is not a release root,
Android APT validation, an archive parser, or a package lifecycle proof.
"""
import datetime
import hashlib
import functools
import http.server
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path


ROOT = Path("/home/builder/repository-proof")


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    ROOT.mkdir()  # Never reuse a previous fixture trust/cache directory.
    repo = ROOT / "repo"
    pool = repo / "pool"
    pool.mkdir(parents=True)
    inventory = json.loads(Path("/home/builder/fixture-input/inventory.json").read_text())
    expected = {}
    for name in ("hello_2.12.3-1_aarch64.deb", "libiconv_1.19_aarch64.deb"):
        entries = [entry for entry in inventory["packages"] if entry["file"] == name]
        data = Path("/home/builder/fixture-input", name).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if len(entries) != 1 or digest != entries[0]["sha256"]:
            raise SystemExit("Fixture input differs from build inventory")
        expected[name] = digest
        (pool / name).write_bytes(data)
    index = repo / "dists/proof/main/binary-aarch64/Packages"
    index.parent.mkdir(parents=True)
    packages = subprocess.check_output(["dpkg-scanpackages", "--multiversion", "pool", "/dev/null"], cwd=repo)
    index.write_bytes(packages)
    # Loopback only inside a --network none container. Unlike file: transport,
    # HTTP exercises archive download/hash checks and produces cache artifacts.
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0),
        functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(repo)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    repo_url = f"http://127.0.0.1:{server.server_address[1]}"
    keyhome = ROOT / "gnupg"
    keyhome.mkdir(mode=0o700)
    os.environ["GNUPGHOME"] = str(keyhome)
    gpg = ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", ""]
    run(gpg + ["--quick-generate-key", "Termi disposable fixture only", "ed25519", "sign", "1d"])
    keyring = ROOT / "fixture-keyring.gpg"
    keyring.write_bytes(subprocess.check_output(gpg + ["--export"]))
    inrelease = repo / "dists/proof/InRelease"
    release = inrelease.with_name("Release")

    def sign(expired=False):
        now = datetime.datetime.now(datetime.timezone.utc)
        date = now - datetime.timedelta(days=2 if expired else 0)
        until = now + datetime.timedelta(days=-1 if expired else 1)
        date_format = "%a, %d %b %Y %H:%M:%S +0000"
        content = index.read_bytes()
        release.write_text(
            "Origin: TermiFixture\nLabel: Disposable local fixture\nSuite: proof\nCodename: proof\n"
            f"Date: {date.strftime(date_format)}\nValid-Until: {until.strftime(date_format)}\n"
            "Architectures: aarch64\nComponents: main\nSHA256:\n"
            f" {hashlib.sha256(content).hexdigest()} {len(content)} main/binary-aarch64/Packages\n")
        run(gpg + ["--armor", "--output", str(inrelease), "--clearsign", str(release)])

    sign()
    valid_signature = inrelease.read_bytes()
    results = []

    def apt_case(label, command, should_pass, prepare_status=None):
        case = ROOT / label
        for relative in ("etc/preferences.d", "etc/apt.conf.d", "state/lists/partial", "cache/archives/partial", "log"):
            (case / relative).mkdir(parents=True, exist_ok=False)
        status = case / "state/status"
        status.write_text(prepare_status or "")
        (case / "etc/sources.list").write_text(
            f"deb [arch=aarch64 signed-by={keyring}] {repo_url} proof main\n")
        # Loaded BEFORE default apt.conf.d, unlike command-line Dir overrides.
        # This prevents the image's housekeeping hooks/global sources leaking in.
        config = case / "apt.conf"
        (case / "etc/apt.conf").write_text("")
        config.write_text(f'Dir::Etc "{case / "etc"}";\n'
                          '#clear APT::Architectures;\nAPT::Architecture "aarch64";\n'
                          'APT::Architectures { "aarch64"; };\n')
        environment = {**os.environ, "APT_CONFIG": str(config)}
        base = ["apt-get", "-o", "APT::Architecture=aarch64",
                "-o", f"Dir::Etc={case / 'etc'}", "-o", f"Dir::State={case / 'state'}",
                "-o", f"Dir::State::status={status}", "-o", f"Dir::Cache={case / 'cache'}",
                "-o", f"Dir::Log={case / 'log'}", "-o", "APT::Sandbox::User=builder",
                "-o", "Acquire::Languages=none", "-o", "Acquire::Check-Date=true",
                "-o", "Acquire::Check-Valid-Until=true", "-o", "APT::Update::Error-Mode=any",
                "-o", "Acquire::AllowInsecureRepositories=false",
                "-o", "APT::Get::AllowUnauthenticated=false"]
        with (case / "apt.log").open("wb") as output:
            update = subprocess.run(base + ["update"], env=environment, stdout=output, stderr=subprocess.STDOUT).returncode
            code = update
            if update == 0 and command:
                code = subprocess.run(base + command, env=environment, stdout=output, stderr=subprocess.STDOUT).returncode
        output = (case / "apt.log").read_text()
        if (code == 0) != should_pass:
            raise RuntimeError(f"Unexpected {label} exit {code}: {output[-6000:]}")
        results.append({"case": label, "update_exit": update, "exit": code,
                        "expected_success": should_pass, "cache": "fresh-empty-per-case",
                        "transport": "offline-container-loopback-http"})
        print(f"APT_FIXTURE_PASS {label} update={update} exit={code}", flush=True)
        return case, output

    case, _ = apt_case("valid", ["--download-only", "--no-install-recommends", "--assume-yes", "install", "hello:aarch64"], True)
    downloaded = {file.name: hashlib.sha256(file.read_bytes()).hexdigest()
                  for file in (case / "cache/archives").glob("*.deb")}
    if downloaded != expected:
        raise RuntimeError(f"Wrong dependency closure or downloaded bytes: {downloaded}")

    inrelease.write_bytes(valid_signature.replace(b"Origin: TermiFixture", b"Origin: ForgedOrigin"))
    apt_case("tampered-signature", [], False)
    inrelease.write_bytes(valid_signature)
    index.write_bytes(packages + b"\nTampered: index\n")
    apt_case("tampered-index", [], False)
    index.write_bytes(packages)
    hello = pool / "hello_2.12.3-1_aarch64.deb"
    original = hello.read_bytes()
    hello.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    apt_case("tampered-deb", ["--download-only", "--no-install-recommends", "--assume-yes", "install", "hello:aarch64"], False)
    hello.write_bytes(original)

    trusted_key = keyring.read_bytes()
    keyring.write_bytes(b"")
    apt_case("missing-trust-root", [], False)
    keyring.write_bytes(trusted_key)
    sign(expired=True)
    apt_case("expired-metadata", [], False)
    sign()
    installed = ("Package: hello\nStatus: install ok installed\nPriority: optional\nSection: misc\n"
                 "Architecture: aarch64\nVersion: 99.0\nMaintainer: Fixture\nDescription: Newer installed fixture\n\n")
    _, output = apt_case("no-implicit-downgrade", ["--simulate", "install", "hello:aarch64"], True, installed)
    if "Inst hello " in output or "Inst hello:" in output:
        raise RuntimeError("APT proposed an implicit downgrade")

    index.write_bytes(packages.replace(b"Architecture: aarch64", b"Architecture: amd64"))
    sign()
    apt_case("incompatible-abi", ["--simulate", "install", "hello:aarch64"], False)
    # Keep public evidence; discard fixture private signing keys before export.
    run(["gpgconf", "--kill", "gpg-agent"])
    shutil.rmtree(keyhome)
    server.shutdown()
    (ROOT / "results.json").write_text(json.dumps({
        "status": "host-fixtures-only-not-android-proof", "results": results,
        "apt_version": subprocess.check_output(["apt-get", "--version"], text=True).splitlines()[0],
        "key_policy": "disposable fixture key, not a production trust root; private key discarded",
        "network": "container has no external network; signed metadata verified afresh against loopback repository",
    }, indent=2) + "\n")
    print("APT_HOST_FIXTURES_COMPLETE; Android lifecycle/trust gate remains separate", flush=True)


if __name__ == "__main__":
    main()
