# Termi approved APT repository

Distribution URL: `https://mannansaood.github.io/termi/apt`.
Scope: Termi (`com.terminal.nextgen`), primary Android user, ARM64, the existing
API26-built private-prefix runtime. Device certification is recorded separately;
this does not promise compatibility on every API26+ device or other ABIs.
The app's package manager remains upstream Termux pkg/APT/dpkg.

The approved application roots are Git, GitHub CLI and the existing hello proof.
APT, Bash, termux-exec and termux-tools are bootstrap backend roots. Only their
resolved runtime dependencies are published. Git's Tcl/Tk GUI, SVN bridge and
Perl features are omitted. OpenSSH, an editor, Python and other tools are not
included. HTTPS Git is supported; use `git commit -m` or configure an installed
editor. GitHub account authorization remains a user action (`gh auth login`).
Git2.56.0 revision1 uses upstream `NO_MMAP=1`: the virtual workspace deliberately
rejects mapped file access, so Git reads those files through ordinary checked
reads instead. This can use more memory for large pack files. Local clone tests
use `--no-local` to avoid Android's hardlink restriction.

## Authority and publication

The APK pins `repository.properties` and `repository-keyring.gpg`. A journaled
migration changes only the original proof source to the HTTPS source, preserving
the bootstrap identity, home and dpkg database. Unknown configurations and
changed keys fail closed. The source's `signed-by` restricts this authority to
this repository; stock Termux keys and repositories are not enabled.

Primary certification fingerprint:
`BB87B4B51BE059A03DBB8AA3E807D1DC6335F51F`.
Signing subkey: `210ACB83274F60F24D3E3F3E035672368292AB62`.
See `authority.json` and `gpg --show-keys --with-colons repository-keyring.gpg`
for exact key expiry. The primary was created for ten years and the subkey for
two years. This is not an anonymous public key fetched at first use.

`codex/apt-repository` holds immutable Debian files, the approved inventory,
runtime dependency resolution and provenance under `public/apt/`. The default
branch holds the publisher, this public authority and the Actions workflow.
Actions must match the inventory to the operator-controlled
`TERMI_APT_INVENTORY_SHA256` variable before signing. Package hashes, identities,
versions, architectures, pool membership, aliases and size limits are checked.
Every catalog change requires an explicit new reviewed inventory hash.
The same approval also pins the source archives, build records and SBOM.
Retained older package versions remain immutable for existing by-hash indexes;
APT selects the highest version. The bounded publisher permits at most90 package
names and180 versioned artifacts, within a512MiB repository budget.

The weekly Monday 04:17 UTC workflow and manual dispatch regenerate Release,
InRelease and detached signatures with a 45-day validity window. They reverify
existing approved package bytes; **renewal does not rebuild or security-update
the packages**. Indexes support Acquire-By-Hash and old immutable index files
are retained. Pages deploys a complete artifact after signature verification.
No mirror fallback or unsigned source is configured. Installed tools continue
working offline. APT rejects expired metadata for updates; cached downloads
are not evidence of fresh network verification.

## Operator procedure

Monitor the scheduled workflow and `apt/renewal.json`, and manually dispatch
`apt_repository.yml` after interruptions. A renewable metadata window replaces
the disposable proof's October27 expiration. GitHub can disable schedules in
inactive public repositories; successful weekly renewal commits normally keep
this repository active, but operators must still check workflow status. If
automation or Pages becomes unavailable, repair it before Valid-Until. Never
set `trusted=yes`, disable signature checks or disable Valid-Until.

Actions secrets `TERMI_APT_SIGNING_SUBKEY` and
`TERMI_APT_SIGNING_PASSPHRASE` contain only an encrypted signing subkey and its
passphrase. The certification key is absent. Repository administrators and
maintainers who can edit trusted workflows are signing authorities in practice.
Restrict those roles and protect workflow changes. The signer runs separately
from source builds; build containers never receive signing secrets.

The local recovery file is
`packages/termux/.local-signing/repository-authority.dpapi`, excluded from Git.
It contains the certification key, signing subkey, passphrase and revocation
certificate encrypted with Windows current-user DPAPI. Back it up together with
the recoverable Windows user profile to operator-controlled secure storage.
Copying this file alone to another account will not make it decryptable.
`provision_signing.py` refuses to replace an existing escrow. Never commit,
upload as a build artifact, or print the decrypted contents.

Before the signing subkey expires, recover the certification key in an isolated
offline signing environment, create a replacement signing subkey, and distribute
an APK with an explicitly reviewed higher-generation trust migration and new
public keyring. Stage the new subkey secret, fingerprint and APK before signing
repository metadata with it. The present migration supports proof-to-v1 only;
future rotations require that reviewed app migration, not silent key replacement.

For suspected signing compromise: disable the publishing workflow, remove the
compromised Actions secrets, retain logs and signed snapshots, and revoke the
subkey with the offline certification authority. Distribute an app update with
a new pinned keyring and monotonic migration, then restore the repository from
reviewed packages. Existing installed programs are not remotely removed. APT's
version rules reject implicit downgrade, but a compromised live signer can
publish malicious higher versions: revocation requires operator/app action.

GitHub CLI's Go build uses a small Android-only subprocess adapter when Termux
linker mode is enabled. It invokes the system shell with positional arguments,
then the existing Termux libc exec hook. It does not interpret arguments as shell
source or change Go runtime argv parsing. Custom child argv[0] is not preserved.
All packages share the app UID, including access to its private storage; neither
APT nor this adapter creates a sandbox against malicious same-UID programs.
SAF/shared storage is never an executable package install root.

GH2.102.0 revision1 pins `github.com/gabriel-vasile/mimetype` v1.4.16 with
explicit Go module sums. Its upstream v1.4.15 dependency was retracted for
quadratic processing of specially crafted CDF files. The package provenance
records this source modification as well as the Android subprocess adapter.

## Verified integration and bootstrap repair

On 2026-10-20, Git2.56.0-1 and GH2.102.0-1 passed installation, reinstall,
local Git commit/clone, HTTPS access and GH child execution in ordinary and
virtual sessions on OnePlus CPH2619 ARM64/API36. The normal terminal UI also
passed. Other package ABIs, Android versions and secondary users remain unverified.

The original immutable bootstrap omitted dpkg's legacy `md5sums` database
records. Its 55 packages were repaired on the test phone by authenticated APT
reinstallation of exact approved versions with `--force-confold`; the source
configuration was compared before/after and `dpkg --audit` is now empty.
The assembler now generates missing records from original Debian payload bytes.
These MD5 records are dpkg compatibility data; package authentication still uses
signed SHA256 metadata. The existing APK-pinned bootstrap was deliberately not
replaced. Fresh installations using that older bootstrap still need this
reconciliation before a clean full dpkg audit; a future bootstrap release must
use an explicit identity migration. The repair asset and device evidence are in
the local app integration checkout, separate from the published build control.
