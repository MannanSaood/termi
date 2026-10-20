#!/usr/bin/env python3
"""One-time Windows operator key provisioning in an isolated signing container.

Root and signing subkey are escrowed using current-user Windows DPAPI. Only the
signing subkey and its passphrase enter GitHub Actions secrets. No secret prints.
"""
import base64
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import secrets
import subprocess

CONTAINER = "termi-repository-signer-01"
REPO = "MannanSaood/termi"
GH = r"C:\Program Files\GitHub CLI\gh.exe"
ESCROW = Path("packages/termux/.local-signing")
PUBLIC = Path("packages/termux/repository")


def docker(arguments, data=None):
    return subprocess.check_output(
        ["docker", "exec", "-i", "-e", "GNUPGHOME=/home/builder/authority", CONTAINER, *arguments],
        input=data,
    )


class Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def protect(data):
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source = Blob(len(data), buffer)
    result = Blob()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(source), "Termi repository offline root", None, None, None, 1, ctypes.byref(result)
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(result.pbData)


def main():
    ESCROW.mkdir(parents=True, exist_ok=True)
    backup = ESCROW / "repository-authority.dpapi"
    if backup.exists():
        raise SystemExit("Existing authority retained; use recovery, never silently replace")
    PUBLIC.mkdir(parents=True, exist_ok=True)
    docker(["mkdir", "-m", "700", "/home/builder/authority"])
    password = secrets.token_urlsafe(48).encode()
    gpg = ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase-fd", "0"]
    docker(gpg + ["--quick-generate-key", "Termi approved package repository <packages@termi.invalid>",
                  "ed25519", "cert", "10y"], password)
    listing = docker(["gpg", "--with-colons", "--list-secret-keys"]).decode()
    primary = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
    docker(gpg + ["--quick-add-key", primary, "ed25519", "sign", "2y"], password)
    listing = docker(["gpg", "--with-colons", "--list-secret-keys"]).decode()
    fingerprints = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
    subkey = fingerprints[1]
    public = docker(["gpg", "--export", primary])
    root = docker(gpg + ["--armor", "--export-secret-keys", primary], password)
    sub = docker(gpg + ["--armor", "--export-secret-subkeys", subkey + "!"], password)
    revocation = docker(["cat", f"/home/builder/authority/openpgp-revocs.d/{primary}.rev"])
    payload = json.dumps(dict(primary=primary, subkey=subkey, passphrase=password.decode(),
                              root=base64.b64encode(root).decode(), signing=base64.b64encode(sub).decode(),
                              revocation=base64.b64encode(revocation).decode())).encode()
    with backup.open("xb") as stream:
        stream.write(protect(payload))
    (PUBLIC / "repository-keyring.gpg").write_bytes(public)
    (PUBLIC / "authority.json").write_text(json.dumps(dict(
        primary=primary, signing_subkey=subkey, root_validity="10 years", subkey_validity="2 years",
        local_recovery="Windows current-user DPAPI escrow; preserve Windows profile and backup",
        automation_authority="signing subkey only; no root certification key in Actions",
    ), indent=2) + "\n", encoding="utf-8")
    for name, value in [("TERMI_APT_SIGNING_SUBKEY", sub), ("TERMI_APT_SIGNING_PASSPHRASE", password)]:
        subprocess.run([GH, "secret", "set", name, "--repo", REPO], input=value, check=True)
    subprocess.run([GH, "variable", "set", "TERMI_APT_SIGNING_FINGERPRINT", "--repo", REPO, "--body", subkey], check=True)
    # Exact known owned path, confined to this newly created container.
    docker(["rm", "-rf", "/home/builder/authority"])
    docker(["mkdir", "-m", "700", "/home/builder/authority"])
    docker(["gpg", "--batch", "--import"], sub)
    print(json.dumps({"primary": primary, "signing_subkey": subkey, "escrow": str(backup)}))


if __name__ == "__main__":
    main()
