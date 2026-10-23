# Termi local package hosting

Read-only LAN hosting while package compilation continues on GitHub. This does
not build packages, clear app data, modify Android sources, deploy Workers or
make unsigned catalog candidates available. The server exposes only the files
in a verified signed snapshot, never the repository checkout or directory lists.

## Start on Windows

Requires Python3.11+ (`pythonw.exe`), PowerShell and Docker Desktop with Linux
containers. Docker verifies existing signatures and all approved file hashes
using a pinned builder image. It runs without network access or private signing
keys. The server itself uses Python's standard library.

From the main Termi checkout, fetch the current public signed snapshot with
byte-preserving checkout settings (run once into a new directory):

```powershell
git -c core.autocrlf=false clone --depth 1 --single-branch --branch codex/apt-repository `
  --config core.autocrlf=false https://github.com/MannanSaood/termi.git local/runtime/repository
./local/Start.ps1 -Repository ./local/runtime/repository/public/apt `
  -Keyring ./packages/termux/repository/repository-keyring.gpg -Bind 192.168.1.5
```

Preserve exact bytes: text line-ending conversion invalidates signed hashes.
Do not use unsigned local staging directories. A stale snapshot must be renewed
through the existing signing process, not by editing dates locally.

```powershell
./local/Start.ps1 -Repository C:/path/to/signed/apt `
  -Keyring C:/path/to/termi-public-repository-keyring.gpg `
  -Bind 192.168.1.5 -Port 8765
```

Use your current Wi-Fi IPv4 address. Bind defaults to loopback for local-only
testing. Keep the snapshot immutable while serving it. Repository files, logs,
process details and verification reports belong under ignored `local/runtime/`
or another local data directory; they are not committed.

Open `http://YOUR-LAN-IP:8765/healthz` to see the actual package count and expiry.
The APT base is `http://YOUR-LAN-IP:8765/apt/main/`. A source entry, when the
phone is available and its existing signed-by key location is confirmed, has
this form:

```text
deb [signed-by=/actual/existing/termi-keyring.gpg] http://YOUR-LAN-IP:8765/apt/main stable main
```

The key path above is explanatory, not an install command. Do not replace
working phone sources blindly, add `trusted=yes`, disable signature/expiry
checks, uninstall the app or restore old backups. LAN HTTP is for this local
development setup; package authentication still uses the existing Termi key.
The APK's endpoint remains unchanged until a separate device migration check.

The computer must stay awake and the phone must reach its LAN address. If
Windows Firewall blocks another device, allow only the Python server's TCP port
from your local subnet; do not disable the firewall or forward the router port.
A successful check on this PC/container does not certify phone connectivity.
An address change requires restarting with the new address and updating the
development client URL. There is no automatic startup or internet exposure.

Stop the exact recorded server with:

```powershell
./local/Stop.ps1
```

## Verification and tests

```powershell
python -m unittest discover -s local -p 'test_*.py' -v
```

`Start.ps1` refuses invalid signatures, inventory mismatch, altered package or
source evidence bytes and expired metadata. Startup pins its verification map
and rechecks the files. The HTTP server supports GET/HEAD and byte ranges;
rejects unlisted files, uploads and directory traversal; stops serving changed
files or expired metadata. Keep runtime data writable only by the local owner.

`check_transport.py` runs with Linux APT and the public keyring to perform a real
signed index update and checksum-exact downloads of `hello`, `openssl` and
`termux-exec`, including epoch filenames. It installs/executes nothing and uses
only temporary isolated APT state. Example inside the pinned Linux builder:

```sh
python3 /work/check_transport.py --url http://YOUR-LAN-IP:8765/apt/main \
  --keyring /trust/repository-keyring.gpg
```

## Catalog status and later hosting

The initial server uses the existing reviewed63package snapshot, not the entire
catalog. Full-catalog and Node/npm source builds continue separately in
[termi-packages Actions](https://github.com/MannanSaood/termi-packages/actions).
New packages need dependency/source/license/runtime review and isolated signing
before they can be served. No signing authority is added to this folder.

The verifier accepts both flat signed pool paths and the planned immutable
release-tag paths, mapping them to the actual verified local files. Later,
Workers can serve the same signed repository paths without rebuilding package
binaries. Workers/Cloudflare account setup is deferred while local hosting is
selected. Main/root/X11 channels must retain their own reviewed snapshots;
this startup script currently serves main only.

Verified setup on2026-10-24: current signed snapshot commit `94f348a` passed
signature, inventory, all package/source-evidence hashes and expiry checks.
Three Windows HTTP tests passed. Actual Linux APT reached the running Windows
LAN server, verified the signed index and downloaded three exact packages,
including two epoch filenames. Safe stop/restart passed. No packages were
installed/executed and no phone or app data was accessed. Another physical LAN
device/firewall path remains untested while the phone is unavailable.
